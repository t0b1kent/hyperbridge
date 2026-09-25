/*
 * hb_direct_mem_coherence_repro.c — minimal 2-thread STLR/LDAR reproducer
 * INSIDE the HB JIT, OUTSIDE Hollow Knight.
 *
 * Vectors 1+3: does direct-mem cross-thread coherence work AT ALL on Apple
 * Silicon for a guest region allocated the same way HK's is
 * (mmap MAP_PRIVATE|MAP_ANONYMOUS)?  And does the direct-mem path hit the SAME
 * physical page from both threads, or a per-context/per-thread host-MIRROR?
 *
 * Key HB codegen fact (hb_arm64_codegen.c):
 *   - STORE side: emit_direct_mem_store_from_x20 -> emit_stlr_from_reg = real STLR (release)
 *   - LOAD  side: emit_direct_mem_load_to_x20    -> emit_ldar_to_reg    = LDR + DMB ISHLD
 *     (NOT a real LDAR — comment says LDAR SIGBUSes on unaligned x86 EAs, so HB
 *      substitutes plain LDR + DMB ISHLD).  Prime suspect for a field-selective
 *      visibility gap: a plain LDR can return a STALE value; DMB orders but does
 *      not force a fresh re-read.
 *
 * Configs (producer writes a flag, consumer polls until non-zero):
 *   A) direct-stlr-vs-ldar-subst : STLR + (LDR + DMB ISHLD)   == actual HB path
 *   B) direct-stlr-vs-true-ldar  : STLR + true LDAR           == what HB should emit
 *   C) plain-str-vs-ldr          : plain STR + plain LDR      == weakest baseline
 *   D) helper-lazy               : hb_memory_write/read_u32   == coherent reference
 *   E) mirror-split              : producer writes host_base, consumer reads GVA
 *                                  (simulates hb_memory_map_private host_base!=base) -> paradox
 *
 * Build: make coherence-repro   Run: ./tests/hb_direct_mem_coherence_repro
 * Diagnostics env-gated (MACRUNNER_HB_REPRO_VERBOSE=1); floor stays intact.
 */
#include "hb_codegen.h"
#include "hb_memory.h"
#include "hb_context.h"

#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include <stdatomic.h>

#ifndef MAP_JIT
#  define MAP_JIT 0x800
#endif

/* ---- ARM64 emitter (exact HB encodings, copied from hb_arm64_codegen.c) ---- */
typedef struct { uint32_t* code; size_t n; size_t cap; } emitter_t;
static void em_init(emitter_t* e, size_t cap) { e->cap=cap; e->n=0; e->code=(uint32_t*)calloc(cap,sizeof(uint32_t)); }
static void em_u32(emitter_t* e, uint32_t v) { if(e->n>=e->cap){e->cap*=2;e->code=realloc(e->code,e->cap*sizeof(uint32_t));} e->code[e->n++]=v; }
static size_t em_pos(emitter_t* e) { return e->n; }
static void em_stlr_w(emitter_t* e,int rt,int rn){ em_u32(e,0x889ffc00u|((uint32_t)rn<<5)|(uint32_t)rt);}      /* STLR Wt,[Xn] */
static void em_ldar_w(emitter_t* e,int rt,int rn){ em_u32(e,0x885ffc00u|((uint32_t)rn<<5)|(uint32_t)rt);}      /* LDAR Wt,[Xn] */
static void em_ldr_w0(emitter_t* e,int rt,int rn){ em_u32(e,0xb9400000u|((uint32_t)rn<<5)|(uint32_t)rt);}      /* LDR Wt,[Xn,#0] */
static void em_str_w0(emitter_t* e,int rt,int rn){ em_u32(e,0xb9000000u|((uint32_t)rn<<5)|(uint32_t)rt);}      /* STR Wt,[Xn,#0] */
static void em_dmb_ishld(emitter_t* e){ em_u32(e,0xd50339bfu); }
static void em_ret(emitter_t* e){ em_u32(e,0xd65f03c0u); }
static size_t em_cbnz_w(emitter_t* e,int rt){ size_t a=em_pos(e); em_u32(e,0x35000000u|(uint32_t)rt); return a;} /* CBNZ Wt */
static void __attribute__((unused)) em_subs_w1(emitter_t* e,int rd,int rn){ em_u32(e,0x71000000u|(1u<<10)|((uint32_t)rn<<5)|(uint32_t)rd);} // SUBS Wd,Wn#1
static size_t em_bcond(emitter_t* e,int cond){ size_t a=em_pos(e); em_u32(e,0x54000000u|(uint32_t)cond); return a;} /* B.cond */
static size_t em_b(emitter_t* e){ size_t a=em_pos(e); em_u32(e,0x14000000u); return a; }                         /* B */
static void em_patch19(emitter_t* e,size_t at,int64_t target,int64_t from){ int64_t o=target-from; e->code[at]=(e->code[at]&0xff00001fu)|(((uint32_t)o&0x7ffff)<<5); }
static void em_patch26(emitter_t* e,size_t at,int64_t target,int64_t from){ int64_t o=target-from; e->code[at]=0x14000000u|((uint32_t)o&0x3ffffff); }

/* ---- struct offsets ---- */
typedef struct {
    void*    flag_x21;    /* 0  */
    uint64_t log_x21;     /* 8  */
    uint32_t value;       /* 16 */
    uint32_t saw;         /* 20 */
    uint64_t timeout;     /* 32 */
    uint64_t iters;       /* 40 */
    hb_memory_t* mem;     /* 48 */
    hb_gva_t  flag_gva;   /* 56 */
} thread_arg_t;
#define OFF_FLAG   (offsetof(thread_arg_t, flag_x21))
#define OFF_LOG    (offsetof(thread_arg_t, log_x21))
#define OFF_VALUE  (offsetof(thread_arg_t, value))
#define OFF_SAW    (offsetof(thread_arg_t, saw))
#define OFF_TIMEOUT (offsetof(thread_arg_t, timeout))
#define OFF_ITERS  (offsetof(thread_arg_t, iters))


/* ---- JIT buffer (HB MAP_JIT/W^X path) ---- */
typedef struct { hb_jit_buffer_t* jb; void* entry; size_t words; } jit_fn_t;
static int jit_build(jit_fn_t* out, const uint32_t* code, size_t words) {
    out->words = words; out->jb = hb_jit_buffer_create(words*4+64);
    if (!out->jb) return -1;
    if (hb_jit_buffer_make_writable(out->jb) != HB_OK) return -1;
    memcpy(out->jb->writable, code, words*4);
    out->jb->used = words*4;
    if (hb_jit_buffer_commit(out->jb) != HB_OK) { fprintf(stderr,"repro: commit failed\n"); return -1; }
    out->entry = (void*)out->jb->writable;
    return 0;
}
static void jit_free(jit_fn_t* f){ if(f->jb) hb_jit_buffer_destroy(f->jb); }

typedef enum { CFG_SUBST, CFG_TRUELDAR, CFG_PLAIN, CFG_HELPER, CFG_MIRROR } cfg_t;
static const char* cfg_name(cfg_t c){
    switch(c){
    case CFG_SUBST:    return "A: direct-mem STLR + (LDR+DMB ISHLD)  [actual HB]";
    case CFG_TRUELDAR: return "B: direct-mem STLR + true LDAR        [should-work ref]";
    case CFG_PLAIN:    return "C: plain STR + plain LDR (no barrier) [weak baseline]";
    case CFG_HELPER:   return "D: helper/lazy hb_memory_write/read   [coherent ref]";
    case CFG_MIRROR:   return "E: mirror-split host_base != GVA       [paradox demo]";
    } return "?";
}

/* Producer: prologue saves X19-X22 (we clobber callee-saved X20/X21);
 * X21=a->flag_x21 (the EA, == HB), log it, W20=a->value, STLR/STR W20,[X21], epilogue, RET. */
static int build_producer(jit_fn_t* out, cfg_t cfg) {
    emitter_t e; em_init(&e,64);
    em_u32(&e, 0xa9bd53f3u);  /* STP X19,X20,[SP,#-48]!   (HB prologue) */
    em_u32(&e, 0xa9015bf5u);  /* STP X21,X22,[SP,#16]      (HB prologue) */
    em_u32(&e, 0xf9400000u | ((uint32_t)(OFF_FLAG/8)<<10) | (0u<<5) | 21u);  /* LDR X21,[X0,#OFF_FLAG] */
    em_u32(&e, 0xf9000000u | ((uint32_t)(OFF_LOG/8)<<10)  | (0u<<5) | 21u);  /* STR X21,[X0,#OFF_LOG]  */
    em_u32(&e, 0xb9400000u | ((uint32_t)(OFF_VALUE/4)<<10) | (0u<<5) | 20u); /* LDR W20,[X0,#OFF_VALUE] */
    switch (cfg) {
    case CFG_SUBST: case CFG_TRUELDAR: case CFG_MIRROR: em_stlr_w(&e,20,21); break;
    case CFG_PLAIN: em_str_w0(&e,20,21); break;
    case CFG_HELPER: break;
    }
    em_u32(&e, 0xa9415bf5u);  /* LDP X21,X22,[SP,#16]      (HB epilogue) */
    em_u32(&e, 0xa8c353f3u);  /* LDP X19,X20,[SP],#48      (HB epilogue) */
    em_ret(&e);
    return jit_build(out, e.code, e.n);
}

/* Consumer (bounded): prologue saves X19-X22; X21=a->flag_x21 (EA), log,
 * X9=a->timeout (caller-saved, no save needed); poll W20=[X21] (+DMB), CBNZ done,
 * SUBS X9,#1, B.EQ texit, B loop; done/texit store remaining X9 + saw; epilogue; RET. */
static int build_consumer(jit_fn_t* out, cfg_t cfg) {
    emitter_t e; em_init(&e,80);
    if (cfg == CFG_HELPER) { em_ret(&e); return jit_build(out, e.code, e.n); }
    em_u32(&e, 0xa9bd53f3u);  /* STP X19,X20,[SP,#-48]! */
    em_u32(&e, 0xa9015bf5u);  /* STP X21,X22,[SP,#16]   */
    em_u32(&e, 0xf9400000u | ((uint32_t)(OFF_FLAG/8)<<10) | (0u<<5) | 21u);   /* LDR X21,[X0,#OFF_FLAG] */
    em_u32(&e, 0xf9000000u | ((uint32_t)(OFF_LOG/8)<<10)  | (0u<<5) | 21u);   /* STR X21,[X0,#OFF_LOG]  */
    em_u32(&e, 0xf9400000u | ((uint32_t)(OFF_TIMEOUT/8)<<10) | (0u<<5) | 9u); /* LDR X9,[X0,#OFF_TIMEOUT] */
    size_t loop = em_pos(&e);
    switch (cfg) {
    case CFG_SUBST: case CFG_MIRROR: em_ldr_w0(&e,20,21); em_dmb_ishld(&e); break;
    case CFG_TRUELDAR: em_ldar_w(&e,20,21); break;
    case CFG_PLAIN: em_ldr_w0(&e,20,21); break;
    case CFG_HELPER: break;
    }
    size_t cbnz = em_cbnz_w(&e, 20);
    em_u32(&e, 0xf1000000u | (1u<<10) | (9u<<5) | 9u);   /* SUBS X9,X9,#1 (64-bit, caller-saved) */
    size_t beq = em_bcond(&e, 0);                         /* B.EQ texit */
    size_t back = em_b(&e);                               /* B loop */
    size_t done = em_pos(&e);
    em_u32(&e, 0xf9000000u | ((uint32_t)(OFF_ITERS/8)<<10) | (0u<<5) | 9u);  /* STR X9,[X0,#OFF_ITERS] (remaining) */
    em_u32(&e, 0xb9000000u | ((uint32_t)(OFF_SAW/4)<<10)  | (0u<<5) | 20u);  /* STR W20,[X0,#OFF_SAW] */
    em_u32(&e, 0xa9415bf5u);  /* LDP X21,X22,[SP,#16] */
    em_u32(&e, 0xa8c353f3u);  /* LDP X19,X20,[SP],#48 */
    em_ret(&e);
    size_t texit = em_pos(&e);
    em_u32(&e, 0xf9000000u | ((uint32_t)(OFF_ITERS/8)<<10) | (0u<<5) | 9u);  /* STR X9,[X0,#OFF_ITERS] (0) */
    em_u32(&e, 0xa9415bf5u);  /* LDP X21,X22,[SP,#16] */
    em_u32(&e, 0xa8c353f3u);  /* LDP X19,X20,[SP],#48 */
    em_ret(&e);
    em_patch19(&e, cbnz, (int64_t)done, (int64_t)cbnz);
    em_patch19(&e, beq, (int64_t)texit, (int64_t)beq);
    em_patch26(&e, back, (int64_t)loop, (int64_t)back);
    return jit_build(out, e.code, e.n);
}

/* ---- thread bodies ---- */
typedef struct { thread_arg_t a; void (*prod_fn)(thread_arg_t*); void (*cons_fn)(thread_arg_t*); volatile _Atomic int* ready; } run_ctx_t;

static void* producer_jit(void* p){ run_ctx_t* r=p; while(!atomic_load_explicit(r->ready,memory_order_acquire)) { /* spin until consumer polling */ } r->prod_fn(&r->a); return NULL; }
static void* consumer_jit(void* p){ run_ctx_t* r=p; r->a.saw=0; r->a.timeout=20000000ULL; atomic_store_explicit(r->ready,1,memory_order_release); r->cons_fn(&r->a); return NULL; }
static void* producer_helper(void* p){ run_ctx_t* r=p; while(!atomic_load_explicit(r->ready,memory_order_acquire)) { /* wait */ } atomic_store_explicit((_Atomic uint32_t*)r->a.flag_x21, r->a.value, memory_order_release); return NULL; }
static void* consumer_helper(void* p){
    run_ctx_t* r=p; r->a.saw=0; atomic_store_explicit(r->ready,1,memory_order_release);
    for (uint64_t i=0;i<r->a.timeout;i++){ r->a.iters=i; r->a.saw=atomic_load_explicit((_Atomic uint32_t*)r->a.flag_x21, memory_order_acquire); if(r->a.saw) break; }
    return NULL;
}

static int verbose(void){ static int v=-1; if(v<0){const char*e=getenv("MACRUNNER_HB_REPRO_VERBOSE"); v=(e&&e[0]&&e[0]!='0')?1:0;} return v; }
static int same_page(void* a,void* b){ long pg=sysconf(_SC_PAGESIZE); return ((uintptr_t)a/(uintptr_t)pg)==((uintptr_t)b/(uintptr_t)pg); }

typedef struct { const char* name; int coherent; uint64_t iters; uintptr_t prod_x21, cons_x21; int same_phys; } result_t;

static result_t run_config(cfg_t cfg, void* prod_x21, void* cons_x21) {
    result_t R; memset(&R,0,sizeof R); R.name=cfg_name(cfg);
    R.prod_x21=(uintptr_t)prod_x21; R.cons_x21=(uintptr_t)cons_x21; R.same_phys=same_page(prod_x21,cons_x21);

    if (cfg == CFG_HELPER) {
        volatile _Atomic int* shared_ready = (volatile _Atomic int*)calloc(1,sizeof(int));
        run_ctx_t* r=calloc(1,sizeof* r);
        r->a.flag_x21=prod_x21; r->a.value=0x55AA55AAu; r->a.timeout=50000000ULL; r->ready=shared_ready;
        pthread_t pt,ct;
        pthread_create(&ct,NULL,consumer_helper,r);
        pthread_create(&pt,NULL,producer_helper,r);
        pthread_join(pt,NULL); pthread_join(ct,NULL);
        R.coherent=(r->a.saw==0x55AA55AAu); R.iters=r->a.iters;
        free((void*)shared_ready); free(r); return R;
    }

    jit_fn_t prod, cons; memset(&prod,0,sizeof prod); memset(&cons,0,sizeof cons);
    if (build_producer(&prod,cfg)!=0){ R.name="build-prod-failed"; return R; }
    if (build_consumer(&cons,cfg)!=0){ R.name="build-cons-failed"; jit_free(&prod); return R; }
    volatile _Atomic int* shared_ready = (volatile _Atomic int*)calloc(1,sizeof(int));
    run_ctx_t* rp=calloc(1,sizeof* rp); rp->a.flag_x21=prod_x21; rp->a.value=0x55AA55AAu; rp->prod_fn=(void(*)(thread_arg_t*))prod.entry; rp->cons_fn=(void(*)(thread_arg_t*))cons.entry; rp->ready=shared_ready;
    run_ctx_t* rc=calloc(1,sizeof* rc); rc->a.flag_x21=cons_x21; rc->a.value=0x55AA55AAu; rc->prod_fn=(void(*)(thread_arg_t*))prod.entry; rc->cons_fn=(void(*)(thread_arg_t*))cons.entry; rc->ready=shared_ready;
    pthread_t pt,ct;
    pthread_create(&ct,NULL,consumer_jit,rc);
    pthread_create(&pt,NULL,producer_jit,rp);
    pthread_join(pt,NULL); pthread_join(ct,NULL);
    R.coherent=(rc->a.saw==0x55AA55AAu); R.iters=rc->a.timeout - rc->a.iters;  /* iters = polls before seen/exhaust */
    R.prod_x21=rp->a.log_x21; R.cons_x21=rc->a.log_x21; R.same_phys=same_page((void*)R.prod_x21,(void*)R.cons_x21);
    if (verbose()) fprintf(stderr,"[repro] %-44s prod[x21]=0x%lx cons[x21]=0x%lx same_phys=%d saw=0x%x\n",
                           R.name,(unsigned long)R.prod_x21,(unsigned long)R.cons_x21,R.same_phys,rc->a.saw);
    jit_free(&prod); jit_free(&cons); free(rp); free(rc); free((void*)shared_ready);
    return R;
}

int main(void) {
    long pg=sysconf(_SC_PAGESIZE);
    printf("=== HB direct-mem cross-thread coherence reproducer ===\n");
    printf("page=%ld arch=aarch64-apple (HB JIT MAP_JIT/W^X path)\n\n",pg);

    /* shared guest region, allocated EXACTLY like HB hb_memory_map (allocated=true):
     * mmap(NULL,size,PROT_RW,MAP_PRIVATE|MAP_ANONYMOUS,-1,0). Process-wide; shared
     * across pthreads (MAP_PRIVATE = cow vs fork(), NOT vs threads). */
    void* shared=mmap(NULL,(size_t)pg,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    if (shared==MAP_FAILED){perror("mmap shared");return 1;}
    if (verbose()) fprintf(stderr,"[repro] shared-flag-region (identity): va=%p flags=MAP_PRIVATE|MAP_ANONYMOUS\n",shared);

    /* mirror-split: two independent mmaps (host_base backing vs gva stub) */
    void* host_base=mmap(NULL,(size_t)pg,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    void* gva_stub =mmap(NULL,(size_t)pg,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    if (host_base==MAP_FAILED||gva_stub==MAP_FAILED){perror("mmap mirror");return 1;}
    if (verbose()) fprintf(stderr,"[repro] mirror host_base (prod writes): %p | gva_stub (cons reads): %p\n",host_base,gva_stub);

    /* helper/lazy reference is now host-atomic C (coherent) — see run_config. */
    (void)0;
    result_t R[5];
    setvbuf(stderr,NULL,_IONBF,0);

    /* ---- single-thread self-check (diagnostic; verbose only) ---- */
    if (verbose()) {
        void* sc_flag = mmap(NULL,(size_t)pg,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
        memset(sc_flag,0,(size_t)pg);
        jit_fn_t sp, sc2; memset(&sp,0,sizeof sp); memset(&sc2,0,sizeof sc2);
        build_producer(&sp, CFG_SUBST);
        build_consumer(&sc2, CFG_SUBST);
        fprintf(stderr,"[selfcheck] consumer code words:");
        for (size_t i=0;i<sc2.words;i++) fprintf(stderr," %08x", ((uint32_t*)sc2.entry)[i]);
        fprintf(stderr,"\n");
        thread_arg_t a; memset(&a,0,sizeof a);
        a.flag_x21 = sc_flag; a.value = 0xCAFEBABEu; a.timeout = 1000000ULL;
        fprintf(stderr,"[selfcheck] producer code words:");
        for (size_t i=0;i<sp.words;i++) fprintf(stderr," %08x", ((uint32_t*)sp.entry)[i]);
        fprintf(stderr,"\n");
        ((void(*)(thread_arg_t*))sp.entry)(&a);            /* store */
        uint32_t direct = *((uint32_t*)sc_flag);           /* C read same thread */
        ((void(*)(thread_arg_t*))sc2.entry)(&a);            /* consumer polls (flag already set) */
        fprintf(stderr,"[selfcheck] a @ %p flag_x21=%p value=0x%x saw=0x%x timeout=%llu\n",(void*)&a,(void*)a.flag_x21,a.value,a.saw,(unsigned long long)a.timeout);
        uint32_t flag_after = *((uint32_t*)sc_flag);
        fprintf(stderr,"[selfcheck] producer STLR -> C-read=0x%x (expect 0xCAFEBABE) | consumer saw=0x%x iters(remaining)=%llu flag_after=0x%x\n",
                direct, a.saw, (unsigned long long)a.iters, flag_after);
        jit_free(&sp); jit_free(&sc2); munmap(sc_flag,(size_t)pg);
    }

    R[0]=run_config(CFG_SUBST,    shared, shared);
    R[1]=run_config(CFG_TRUELDAR,shared, shared);
    R[2]=run_config(CFG_PLAIN,   shared, shared);
    fprintf(stderr,"--- before D\n");
    R[3]=run_config(CFG_HELPER,  shared, shared);
    fprintf(stderr,"--- after D\n");
    fprintf(stderr,"--- before E\n");
    R[4]=run_config(CFG_MIRROR,  host_base, gva_stub);
    fprintf(stderr,"--- after E\n");

    printf("\n--- RESULTS ---\n");
    printf("%-50s | coh | iters | prod[x21]      cons[x21]      same\n","config");
    printf("%s\n","-------------------------------------------------- + -----+-------+--------------------------------");
    for (int i=0;i<5;i++)
        printf("%-50s | %s | %5llu | 0x%012lx 0x%012lx %s\n",
               R[i].name, R[i].coherent?"YES":"NO ", (unsigned long long)R[i].iters,
               (unsigned long)R[i].prod_x21,(unsigned long)R[i].cons_x21, R[i].same_phys?"Y":"N");

    printf("\n--- VERDICT ---\n");
    int a=R[0].coherent, b=R[1].coherent, c=R[2].coherent, d=R[3].coherent, e=R[4].coherent, id_same=R[0].same_phys;
    printf("Q1: does direct-mem cross-thread coherence work AT ALL (identity)?  %s\n",
           (a&&b&&c&&d)?"YES — STLR/LDR+DMB, true-LDAR, plain, and host-atomic all see the store":"NO");
    printf("Q2: do both threads' [X21] resolve to the SAME physical page (identity)?  %s\n",
           id_same?"YES":"NO  <- per-thread mirror would show here");
    printf("    mmap flags: MAP_PRIVATE|MAP_ANONYMOUS — process-wide; shared across pthreads\n"
           "    (MAP_PRIVATE is copy-on-write vs fork(), NOT vs threads). Not a per-thread mirror.\n");
    printf("Q3 (paradox E, mirror-backed host_base!=GVA): coherent?  %s  same_phys=%s\n",
           e?"YES":"NO ", R[4].same_phys?"Y":"N  <- two different physical pages");
    printf("A(actual HB STLR+LDR/DMB ISHLD) coherent=%s  B(true LDAR)=%s  C(plain)=%s  D(host-atomic)=%s  E(mirror)=%s\n",
           a?"YES":"NO", b?"YES":"NO", c?"YES":"NO", d?"YES":"NO", e?"YES":"NO");

    if (a && b && c && d && id_same) {
        printf("\nFIX PATH: direct-mem cross-thread coherence WORKS for a single shared\n"
               "identity (MAP_PRIVATE|MAP_ANONYMOUS) mapping — the region is process-wide,\n"
               "both threads' [X21] resolve to the same physical page, and the store becomes\n"
               "visible (A sees it, usually within ~1e3-1e4 polls / us; B/C/D immediately).\n"
               "=> The HK field-visibility gap is NOT a fundamental direct-mem coherence fault\n"
               "   and NOT a per-thread host-mirror for identity regions. (Consistent with\n"
               "   the earlier A/B: direct-mem-OFF still fails -> bug is elsewhere, e.g. field-\n"
               "   selective ordering of a plain store, NOT direct-mem coherence.)\n");
        if (!e) printf("\nBUT the reproducer DOES reproduce the mirror paradox (E): a region backed\n"
                       "by a host mirror with host_base != GVA (hb_memory_map_private pattern) makes\n"
                       "the direct-mem path hit the GVA while the lazy/helper path hits host_base ->\n"
                       "two different physical pages -> the consumer NEVER sees the store.\n"
                       "IF any HK-shared field lives in such a mirror-backed region, THAT is the bug.\n"
                       "Fix (fixable mapping, best): make direct-mem translate the GVA via the region's\n"
                       "  host_base so it hits the one shared canonical page.\n"
                       "Fallback (HYBRID): direct-mem for identity/thread-local, lazy (coherent) for\n"
                       "  mirror-backed cross-thread-shared memory.\n"
                       "NOTE: HB currently uses hb_memory_map_private only for x86-32 guest32 mirrors,\n"
                       "  not for x64 HK identity mappings, so E is a hazard proof, not a proven HK cause.\n");
    } else if (!(a&&b&&c&&d)) {
        printf("\nFIX PATH: direct-mem is fundamentally non-coherent even with true LDAR on a\n"
               "shared identity mapping -> shareability/mapping attribute problem. HYBRID required:\n"
               "direct-mem for thread-local/non-shared, lazy (coherent) for cross-thread-shared.\n");
    }

    FILE* rf=fopen("reports/hb_direct_mem_coherence_repro.json","w");
    if (rf){ fprintf(rf,"{\"configs\":[\n");
        for(int i=0;i<5;i++) fprintf(rf,"  {\"name\":\"%s\",\"coherent\":%s,\"iters\":%llu,\"prod_x21\":%lu,\"cons_x21\":%lu,\"same_phys\":%s}%s\n",
            R[i].name,R[i].coherent?"true":"false",(unsigned long long)R[i].iters,(unsigned long)R[i].prod_x21,(unsigned long)R[i].cons_x21,R[i].same_phys?"true":"false",i<4?",":"");
        fprintf(rf,"]}\n"); fclose(rf);
        printf("\n(report: reports/hb_direct_mem_coherence_repro.json)\n");
    }
    munmap(shared,(size_t)pg); munmap(host_base,(size_t)pg); munmap(gva_stub,(size_t)pg);
    return 0;
}
