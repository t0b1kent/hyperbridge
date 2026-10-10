/* 0086 Windows x86-64 machine-state / exception probe.
 * Build (Windows x64): x86_64-w64-mingw32-gcc -O1 -std=c11 -Wall -Wextra windows_probe.c -o windows_probe.exe
 * MSVC x64 developer prompt: cl /nologo /O1 /W4 windows_probe.c
 * Portable manifest only: cc -std=c11 -DLIST_ONLY windows_probe.c -o windows_list
 * No Windows compilation or execution was available during preparation.
 * The Windows source uses only Win32 APIs and generated instruction bytes.
 * Hardware vector/error-code are not supplied in Windows CONTEXT: always NA,
 * never inferred from an NTSTATUS. VEH records preserve the unmodified context.
 * See WINDOWS_NOTES.md for explicit implementation limits and safety exclusions.
 */
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <stdarg.h>
#include <inttypes.h>
#include <wchar.h>

/* CANONICAL_MATRIX_BEGIN: copied verbatim into each single-file C program. */
#define MAX_CELLS 16000
#define CPUID_LEAF_BOUND 64
#define CPUID_SUBLEAF_BOUND 63
enum {K_CPUID,K_XGETBV,K_FEATURE,K_SEGREAD,K_SELECTOR,K_SEGLOAD,K_FLAGS,K_TRAP,K_PREFIX,K_MEMORY,K_STEP,K_TIMING,K_WINDOWS};
typedef struct {char name[160]; unsigned kind,a,b,c; const char *hex,*gate;} Cell;
static Cell cells[MAX_CELLS]; static unsigned cell_count;
static void add_cell(unsigned k,unsigned a,unsigned b,unsigned c,const char *name,const char *hex,const char *gate){
 Cell *p; if(cell_count>=MAX_CELLS){fprintf(stderr,"matrix overflow\n");exit(2);} p=&cells[cell_count++]; memset(p,0,sizeof(*p));p->kind=k;p->a=a;p->b=b;p->c=c;p->hex=hex;p->gate=gate; snprintf(p->name,sizeof p->name,"%s",name);
}
static void build_cells(void){
 char n[160]; unsigned r,l,s,i,j; const unsigned sahf_patterns[4]={0,0xff,0x55,0xaa}; const unsigned base[3]={0,0x40000000u,0x80000000u};
 for(r=0;r<3;r++)for(l=0;l<=CPUID_LEAF_BOUND;l++)for(s=0;s<=CPUID_SUBLEAF_BOUND;s++){snprintf(n,sizeof n,"B1.cpuid.leaf_%08x.sub_%08x",base[r]+l,s);add_cell(K_CPUID,base[r]+l,s,0,n,"0fa2","");}
 for(r=0;r<3;r++){snprintf(n,sizeof n,"B1.cpuid.outside_window_%08x",base[r]+CPUID_LEAF_BOUND+1);add_cell(K_CPUID,base[r]+CPUID_LEAF_BOUND+1,0,1,n,"0fa2","");}
 add_cell(K_CPUID,0xffffffffu,0xffffffffu,1,"B1.cpuid.outside_all_ffffffff","0fa2","");
 for(i=0;i<2;i++){snprintf(n,sizeof n,"B1.xgetbv.%u",i);add_cell(K_XGETBV,i,0,0,n,"0f01d0",i?"xgetbv1":"osxsave");}
 #define FEAT(N,H,G) add_cell(K_FEATURE,0,0,0,"B1.feature." N,H,G)
 FEAT("sse3","f20f7cc0","sse3"); FEAT("ssse3","660f3800c0","ssse3");FEAT("sse41","660f3817c0","sse41");FEAT("sse42","f2480f38f1c0","sse42");
 FEAT("avx","c5fc57c0","avx");FEAT("avx2","c5fdefc0","avx2");FEAT("fma","c4e27d98c0","fma");FEAT("f16c","c4e27913c0","f16c");
 FEAT("avx512f","62f17d48efc0","avx512f");FEAT("avx512dq","62f1fd4856c0","avx512dq");FEAT("avx512bw","62f17d48fcc0","avx512bw");FEAT("avx512vl","62f17d08efc0","avx512vl");
 FEAT("avx512cd","62f27d48c4c0","avx512cd");FEAT("avx512ifma","62f2fd48b4c0","avx512ifma");FEAT("avx512vbmi","62f27d488dc0","avx512vbmi");FEAT("avx512vbmi2","62f3fd4870c000","avx512vbmi2");
 FEAT("avx512vnni","62f27d4850c0","avx512vnni");FEAT("avx512bitalg","62f27d4854c0","avx512bitalg");FEAT("avx512vpopcntdq","62f27d4855c0","avx512vpopcntdq");
 FEAT("bmi1","c4e278f3c8","bmi1");FEAT("bmi2","c4e2fbf5c0","bmi2");FEAT("adx","660f38f6c0","adx");FEAT("popcnt","f3480fb8c0","popcnt");FEAT("lzcnt","f3480fbdc0","lzcnt");
 FEAT("movbe","480f38f003","movbe");FEAT("rdrand","480fc7f0","rdrand");FEAT("rdseed","480fc7f8","rdseed");FEAT("sha","0f38c8c0","sha");FEAT("aes","660f38dcc0","aes");FEAT("pclmul","660f3a44c000","pclmul");
 FEAT("vaes","c4e27ddcc0","vaes");FEAT("vpclmul","c4e37d44c000","vpclmul");FEAT("gfni","660f3acec000","gfni");FEAT("clflushopt","660fae3b","clflushopt");FEAT("clwb","660fae33","clwb");
 FEAT("rdfsbase","f3480faec0","fsgsbase");FEAT("rdgsbase","f3480faec8","fsgsbase");FEAT("wrfsbase_same","f3480faed0","fsgsbase");FEAT("wrgsbase_same","f3480faed8","fsgsbase");
 FEAT("cmpxchg16b","480fc70b","cx16");FEAT("lahf64","9f","lahf64");FEAT("prefetchw","0f0d0b","prefetchw");FEAT("fxsave","480fae03","fxsr");
 FEAT("xsave","480fae23","osxsave");FEAT("xsaveopt","480fae33","xsaveopt");FEAT("xsavec","480fc723","xsavec");FEAT("serialize","0f01e8","serialize");FEAT("rdpid","f30fc7f8","rdpid");FEAT("rdtscp","0f01f9","rdtscp");FEAT("rdtsc","0f31","tsc");
 #undef FEAT
 {const char *name[]={"sgdt","sidt","sldt","str","smsw","cs","ss","ds","es","fs","gs"};const char *hex[]={"0f0103","0f010b","0f00c0","0f00c8","0f01e0","668cc8","668cd0","668cd8","668cc0","668ce0","668ce8"};for(i=0;i<11;i++){snprintf(n,sizeof n,"B2.read.%s",name[i]);add_cell(K_SEGREAD,i,0,0,n,hex[i],"");}}
 {const char *op[]={"lar","lsl","verr","verw"};const char *h[]={"480f02c3","480f03c3","0f00e3","0f00eb"};for(i=0;i<4;i++)for(j=0;j<10;j++){snprintf(n,sizeof n,"B2.%s.selector_%u",op[i],j);add_cell(K_SELECTOR,i,j,0,n,h[i],"");}}
 {const char *seg[]={"ds","es","fs","gs","ss"};const char *h[]={"8ed8","8ec0","8ee0","8ee8","8ed0"};for(i=0;i<5;i++)for(j=0;j<3;j++){snprintf(n,sizeof n,"B2.load_%s.selector_%s",seg[i],j==0?"zero":j==1?"current":"invalid");add_cell(K_SEGLOAD,i,j,0,n,h[i],"");}}
 add_cell(K_FLAGS,0,0,0,"B3.pushfq","9c58","");for(i=0;i<64;i++){snprintf(n,sizeof n,"B3.popfq.toggle_bit_%02u",i);add_cell(K_FLAGS,1,i,0,n,"9d","");}
 add_cell(K_FLAGS,2,0,0,"B3.lahf","9f","");for(i=0;i<4;i++){snprintf(n,sizeof n,"B3.sahf.pattern_%02x",sahf_patterns[i]);add_cell(K_FLAGS,3,i,0,n,"9e","");}
 add_cell(K_TRAP,0,0,0,"B4.int3.CC","cc","");add_cell(K_TRAP,0,0,0,"B4.int3.CD03","cd03","");add_cell(K_TRAP,0,0,0,"B4.icebp","f1","");
 for(i=0;i<256;i++){static char inthex[256][5];snprintf(n,sizeof n,"B4.int.vector_%02x",i);snprintf(inthex[i],5,"cd%02x",i);add_cell(K_TRAP,1,i,0,n,inthex[i],(i==0x80||i==0x2e)?"SKIP_SYSCALL":"");}
 #define TRAP(N,H) add_cell(K_TRAP,0,0,0,"B4." N,H,"")
 TRAP("into64","ce");TRAP("ud0","0fff c0");TRAP("ud1","0fb9c0");TRAP("ud2","0f0b");TRAP("hlt","f4");TRAP("cli","fa");TRAP("sti","fb");add_cell(K_TRAP,2,0,0,"B4.in_byte","ec","SKIP_SAFETY");add_cell(K_TRAP,2,0,0,"B4.out_byte","ee","SKIP_SAFETY");add_cell(K_TRAP,2,0,0,"B4.ins_byte","6c","SKIP_SAFETY");add_cell(K_TRAP,2,0,0,"B4.outs_byte","6e","SKIP_SAFETY");TRAP("rdmsr","0f32");TRAP("rdpmc","0f33");TRAP("lock_nop","f090");TRAP("overlong16","66666666666666666666666666666690");
 TRAP("noncanonical_data","488b00");TRAP("noncanonical_stack","50");TRAP("noncanonical_jump","ffe0");TRAP("noncanonical_return","c3");TRAP("misaligned_movaps","0f2803");TRAP("misaligned_movntdqa","660f382a03");TRAP("misaligned_cmpxchg16b","480fc70b");TRAP("div_zero","48f7f3");TRAP("div_overflow","48f7f3");TRAP("x87_deferred","d9e8d9eedef9 9b");TRAP("sse_unmasked","0f57c00f5ec0");
 #undef TRAP
 {const char *danger[]={"wrmsr","xsetbv","invlpg","lgdt","lidt","lldt","ltr","clts","swapgs"};for(i=0;i<9;i++){snprintf(n,sizeof n,"B4.privileged.%s",danger[i]);add_cell(K_TRAP,2,i,0,n,"","SKIP_SAFETY");}for(i=0;i<16;i++)for(j=0;j<4;j++){snprintf(n,sizeof n,"B4.privileged.%s_%s%u",j&1?"write":"read",j<2?"cr":"dr",i);if(!(j&1)){static char control_read_hex[16][2][9];snprintf(control_read_hex[i][j/2],9,"%02x0f%02x%02x",i>=8?0x44:0x40,j<2?0x20:0x21,0xc0+((i&7)<<3));add_cell(K_TRAP,3,i,j,n,control_read_hex[i][j/2],"");}else add_cell(K_TRAP,2,i,j,n,"","SKIP_SAFETY");}}
 {const char *op[]={"nop","add","mov","lea","xor","imul","bsf","bsr","popcnt","lzcnt","movzx","xchg","cmpxchg","xadd","push","pop","ret","movaps","movsd","cpuid"};const char *h[]={"90","01d8","89d8","8d03","31d8","0fafc3","0fbcc3","0fbdc3","f30fb8c3","f30fbdc3","0fb6c3","87d8","0fb1d8","0fc1d8","50","58","c3","0f28c0","f20f10c0","0fa2"};for(i=0;i<20;i++)for(j=0;j<8;j++){snprintf(n,sizeof n,"B4.prefix.%s.order_%u",op[i],j);add_cell(K_PREFIX,i,j,0,n,h[i],"");}}
 {const char *m[]={"push_unmapped_stack","call_unmapped_stack","pop_unmapped_destination","rep_movsb_fault","rep_stosb_fault","rep_cmpsb_fault","rep_scasb_fault","xchg_readonly","cmpxchg_readonly_equal","cmpxchg_readonly_unequal","xadd_readonly","add_readonly","enter_fault","leave_fault","crosspage_mov_u64","crosspage_movsb","crosspage_sse","crosspage_avx","masked_avx_zero","masked_avx512_zero","gather_avx2_partial"};for(i=0;i<21;i++){snprintf(n,sizeof n,"B5.%s",m[i]);add_cell(K_MEMORY,i,0,0,n,"","");}}
 {const char *m[]={"nop","popfq_set_tf","pushfq","mov_ss","pop_ss64","rep_movsb","cpuid","rdtsc","syscall_list_only","int3","int_cd03","memory_fault","popfq_clear_tf"};for(i=0;i<13;i++){snprintf(n,sizeof n,"B6.%s",m[i]);add_cell(K_STEP,i,0,0,n,"","");}}
 {const char *m[]={"monotonic","back_to_back","cpuid","loop1000","syscall","signal_return","clock_relation"};for(i=0;i<7;i++){snprintf(n,sizeof n,"B7.%s",m[i]);add_cell(K_TIMING,i,0,0,n,"","");}}
 add_cell(K_WINDOWS,0,0,0,"D.windows.suspended_thread_context","","");add_cell(K_WINDOWS,1,0,0,"D.windows.capture_context","","");
 add_cell(K_FEATURE,0,0,0,"B1.feature.avx512bf16","62f27e4852c0","avx512bf16");
 add_cell(K_FEATURE,0,0,0,"B1.feature.avx512fp16","62f57c4858c0","avx512fp16");
 add_cell(K_FEATURE,0,0,0,"B1.feature.avx512vp2intersect","62f27f4868c0","avx512vp2intersect");
 add_cell(K_FEATURE,0,0,0,"B1.feature.avx512er","62f27d48c8c0","avx512er");
 add_cell(K_FEATURE,0,0,0,"B1.feature.avx5124vnniw","62f27f485203","avx5124vnniw");
 add_cell(K_FEATURE,0,0,0,"B1.feature.avx5124fmaps","62f27f489a03","avx5124fmaps");
 add_cell(K_FEATURE,0,0,0,"B1.feature.avx512pf","62f27d49c60c83","avx512pf");

}
/* CANONICAL_MATRIX_END */




#if !defined(LIST_ONLY)
#if !defined(_WIN32) || (!defined(_M_X64) && !defined(__x86_64__))
#error This execution branch requires Windows x64. Use -DLIST_ONLY on other hosts.
#endif
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif
#ifndef WINVER
#define WINVER _WIN32_WINNT
#endif
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#define TRACE_MAX 40
#define LINE_CAP 1048576
#define PAGE_BYTES 4096
#define REGION_BYTES (512 * 1024)
#define CODE_BYTES (16 * 1024)
#define DATA_OFFSET (32 * 1024)
#define SNAP_OFFSET (128 * 1024)
#define ALIGN16 __declspec(align(16))

typedef struct { uint64_t gpr[16], flags; uint16_t seg[6]; uint8_t pad[12]; ALIGN16 unsigned char fx[512]; } SNAP;
typedef struct {unsigned status;DWORD64 mask;DWORD length[4];unsigned char feature[4][2048];} EXTENDED;
typedef struct { EXCEPTION_RECORD record; CONTEXT context; EXTENDED extended; } TRAP;
typedef BOOL (WINAPI *GET_XMASK)(PCONTEXT,DWORD64*);
typedef PVOID (WINAPI *LOCATE_XSTATE)(PCONTEXT,DWORD,DWORD*);
static GET_XMASK get_xmask;static LOCATE_XSTATE locate_xstate;
#ifndef CONTEXT_XSTATE
#define CONTEXT_XSTATE (0x00100000L | 0x00000040L)
#endif
static void capture_extended(PCONTEXT c,EXTENDED *e){static const DWORD features[4]={2,5,6,7};unsigned i;if(!get_xmask||!locate_xstate){e->status=1;return;}if((c->ContextFlags&CONTEXT_XSTATE)!=CONTEXT_XSTATE){e->status=2;return;}if(!get_xmask(c,&e->mask)){e->status=3;return;}e->status=4;for(i=0;i<4;i++){DWORD length=0;PVOID source;if(!(e->mask&(UINT64_C(1)<<features[i])))continue;source=locate_xstate(c,features[i],&length);if(!source||length>sizeof(e->feature[i])){e->status=5;continue;}e->length[i]=length;memcpy(e->feature[i],source,length);}}

typedef struct {
 unsigned char *region, *code, *data, *watch, *test, *resume, *cleanup, *code_end;
 size_t pc, instruction_length; uint64_t initial[16], entry_rsp, safe_rsp;
 SNAP *before, *after; unsigned char *saved_fx;
 unsigned char setup[128], instruction[128]; size_t setup_n, instruction_n;
 TRAP *traps; unsigned trap_count; DWORD owner_thread;
 int active, stepping, steps_left, stopped, handler_edited_fp, code_error;
 unsigned xsave_mask, step_fault_offset, arm_tf, ret_zero_target;
 unsigned page_size; const char *skip; const char *kind;
 DWORD allocation_error, protect_error;
} RUN;
static RUN *volatile current;
static unsigned has_avx_setup,has_avx512_setup;
static uint64_t checksum = UINT64_C(14695981039346656037);
static unsigned lines;
static char out[LINE_CAP]; static size_t out_n;

static void append(const char *format, ...) { va_list ap; int n; size_t avail = sizeof(out)-out_n; if(avail<2){fputs("ERROR output_overflow\n",stderr);exit(4);} va_start(ap,format); n=vsnprintf(out+out_n,avail,format,ap); va_end(ap); if(n<0)return; if((size_t)n>=avail){fputs("ERROR output_overflow\n",stderr);exit(4);} out_n += (size_t)n; }
static void emit_line(void) { size_t i; out[out_n]=0; puts(out); for(i=0;i<out_n;i++){checksum^=(unsigned char)out[i];checksum*=UINT64_C(1099511628211);} checksum^=10;checksum*=UINT64_C(1099511628211);lines++;out_n=0; }
static void rawhex(const unsigned char *p,size_t n) { size_t i;for(i=0;i<n;i++)append("%02x",p[i]); }
static uint16_t u16(const void *p){uint16_t v;memcpy(&v,p,2);return v;}
static uint32_t u32(const void *p){uint32_t v;memcpy(&v,p,4);return v;}
static uint64_t u64(const void *p){uint64_t v;memcpy(&v,p,8);return v;}
static void address(RUN *r,uint64_t v) {
 if(r && v>=(uint64_t)(uintptr_t)r->data && v<(uint64_t)(uintptr_t)r->data+16*PAGE_BYTES)append("data+0x%llx",(unsigned long long)(v-(uint64_t)(uintptr_t)r->data));
 else if(r && v>=(uint64_t)(uintptr_t)r->region && v<(uint64_t)(uintptr_t)r->region+REGION_BYTES) append("region+0x%llx",(unsigned long long)(v-(uint64_t)(uintptr_t)r->region));
 else if(r && r->entry_rsp && v>=r->entry_rsp-1024*1024 && v<=r->entry_rsp+4096)append("stack%+lld",(long long)(v-r->entry_rsp));
 else append("0x%016llx",(unsigned long long)v);
}
static void context_out(RUN *r,const char *tag,const CONTEXT *c) {
 const uint64_t g[16]={c->Rax,c->Rcx,c->Rdx,c->Rbx,c->Rsp,c->Rbp,c->Rsi,c->Rdi,c->R8,c->R9,c->R10,c->R11,c->R12,c->R13,c->R14,c->R15};
 const char *names[16]={"rax","rcx","rdx","rbx","rsp","rbp","rsi","rdi","r8","r9","r10","r11","r12","r13","r14","r15"};unsigned i;
 append(" %s.ContextFlags=%08lx %s.Rip=",tag,(unsigned long)c->ContextFlags,tag);address(r,c->Rip);
 append(" %s.EFlags=%08lx",tag,(unsigned long)c->EFlags);
 for(i=0;i<16;i++){append(" %s.%s=",tag,names[i]);address(r,g[i]);}
 append(" %s.segments=%04x,%04x,%04x,%04x,%04x,%04x",tag,c->SegCs,c->SegSs,c->SegDs,c->SegEs,c->SegFs,c->SegGs);
 append(" %s.Dr0=%016llx %s.Dr1=%016llx %s.Dr2=%016llx %s.Dr3=%016llx %s.Dr6=%016llx %s.Dr7=%016llx",tag,(unsigned long long)c->Dr0,tag,(unsigned long long)c->Dr1,tag,(unsigned long long)c->Dr2,tag,(unsigned long long)c->Dr3,tag,(unsigned long long)c->Dr6,tag,(unsigned long long)c->Dr7);
 append(" %s.MxCsr=%08lx %s.x87_cw=%04x %s.x87_sw=%04x %s.x87_tw=%02x %s.FOP=%04x %s.x87_ip=%08lx %s.x87_dp=%08lx %s.fx_mxcsr=%08lx %s.MXCSR_MASK=%08lx",tag,(unsigned long)c->MxCsr,tag,c->FltSave.ControlWord,tag,c->FltSave.StatusWord,tag,c->FltSave.TagWord,tag,c->FltSave.ErrorOpcode,tag,(unsigned long)c->FltSave.ErrorOffset,tag,(unsigned long)c->FltSave.DataOffset,tag,(unsigned long)c->FltSave.MxCsr,tag,(unsigned long)c->FltSave.MxCsr_Mask);
 append(" %s.FltSave=",tag);rawhex((const unsigned char*)&c->FltSave,sizeof(c->FltSave));
 append(" %s.VectorControl=%016llx %s.DebugControl=%016llx %s.LastBranchToRip=",tag,(unsigned long long)c->VectorControl,tag,(unsigned long long)c->DebugControl,tag);address(r,c->LastBranchToRip);
 append(" %s.LastBranchFromRip=",tag);address(r,c->LastBranchFromRip);append(" %s.LastExceptionToRip=",tag);address(r,c->LastExceptionToRip);append(" %s.LastExceptionFromRip=",tag);address(r,c->LastExceptionFromRip);
}
static void snapshot_out(RUN *r,const char *tag,const SNAP *s){unsigned i;const char *names[16]={"rax","rcx","rdx","rbx","rsp","rbp","rsi","rdi","r8","r9","r10","r11","r12","r13","r14","r15"};for(i=0;i<16;i++){append(" %s.%s=",tag,names[i]);address(r,s->gpr[i]);}append(" %s.flags=%016llx %s.seg_ES_CS_SS_DS_FS_GS=",tag,(unsigned long long)s->flags,tag);for(i=0;i<6;i++)append("%s%04x",i?",":"",s->seg[i]);append(" %s.x87_cw=%04x %s.x87_sw=%04x %s.mxcsr=%08x %s.mxcsr_mask=%08x %s.fx=",tag,u16(s->fx),tag,u16(s->fx+2),tag,u32(s->fx+24),tag,u32(s->fx+28),tag);rawhex(s->fx,512);}
static void b(RUN*r,unsigned v){if(r->pc>=CODE_BYTES){r->code_error=1;return;}r->code[r->pc++]=(unsigned char)v;}
static void d32(RUN*r,uint32_t v){unsigned i;for(i=0;i<4;i++)b(r,v>>(8*i));}
static void d64(RUN*r,uint64_t v){unsigned i;for(i=0;i<8;i++)b(r,(unsigned)(v>>(8*i)));}
static void bytes(RUN*r,const unsigned char*p,size_t n){size_t i;for(i=0;i<n;i++)b(r,p[i]);}
static void disp(RUN*r,const void*p){intptr_t delta=(const unsigned char*)p-(r->code+r->pc+4);if(delta<INT32_MIN||delta>INT32_MAX)r->code_error=1;d32(r,(uint32_t)(int32_t)delta);}
static void mov_imm(RUN*r,unsigned reg,uint64_t v){b(r,reg<8?0x48:0x49);b(r,0xb8+(reg&7));d64(r,v);}
static void store(RUN*r,unsigned reg,void*p){b(r,reg<8?0x48:0x4c);b(r,0x89);b(r,0x05|((reg&7)<<3));disp(r,p);}
static void load(RUN*r,unsigned reg,const void*p){b(r,reg<8?0x48:0x4c);b(r,0x8b);b(r,0x05|((reg&7)<<3));disp(r,p);}
static void fx(RUN*r,unsigned opcode,void*p){b(r,0x48);b(r,0x0f);b(r,0xae);b(r,0x05|(opcode<<3));disp(r,p);}
static void snapshot_code(RUN*r,SNAP*s){unsigned i;for(i=0;i<16;i++)store(r,i,&s->gpr[i]);b(r,0x9c);b(r,0x8f);b(r,0x05);disp(r,&s->flags);for(i=0;i<6;i++){b(r,0x8c);b(r,0x05|(i<<3));disp(r,&s->seg[i]);}fx(r,0,s->fx);if(r->xsave_mask){unsigned char *area=r->region+(s==r->before?196608:212992);b(r,0x9c);mov_imm(r,0,r->xsave_mask);mov_imm(r,2,0);fx(r,4,area);load(r,0,&s->gpr[0]);load(r,2,&s->gpr[2]);b(r,0x9d);}}

static LONG CALLBACK veh(EXCEPTION_POINTERS *ep){RUN*r=current;unsigned n;CONTEXT*c;DWORD code,saved_tf;
 if(!r||!r->active||GetCurrentThreadId()!=r->owner_thread)return EXCEPTION_CONTINUE_SEARCH;
 c=ep->ContextRecord;code=ep->ExceptionRecord->ExceptionCode;saved_tf=c->EFlags&0x100;
 /* Do not swallow unrelated loader, CRT or instrumentation exceptions. */
 if(c->Rip<(DWORD64)(uintptr_t)r->test||c->Rip>(DWORD64)(uintptr_t)r->resume){
  /* The only accepted out-of-code event is the known zero RET target.
     The seeded stack is zero-filled, independent of prefix operand width.
     The outer owned-child process still bounds every other dispatch outcome. */
  if(!(r->ret_zero_target&&c->Rip==0&&code==EXCEPTION_ACCESS_VIOLATION&&ep->ExceptionRecord->NumberParameters>=2&&ep->ExceptionRecord->ExceptionInformation[0]==8&&ep->ExceptionRecord->ExceptionInformation[1]==0))return EXCEPTION_CONTINUE_SEARCH;
 }
 n=r->trap_count++;if(n>=TRACE_MAX)return EXCEPTION_CONTINUE_SEARCH;
 r->traps[n].record=*ep->ExceptionRecord;r->traps[n].context=*c;capture_extended(c,&r->traps[n].extended);
 if(ep->ExceptionRecord->ExceptionFlags&EXCEPTION_NONCONTINUABLE)return EXCEPTION_CONTINUE_SEARCH;
 /* Original FP state has already been copied. Mask only the resumed image. */
 c->EFlags &= ~(DWORD)(0x100|0x400|0x40000); /* TF, DF, AC: never leak to compiler code. */
 c->MxCsr |= 0x1f80;c->FltSave.MxCsr|=0x1f80;c->FltSave.ControlWord|=0x3f;r->handler_edited_fp=1;
 if(r->stepping && code!=EXCEPTION_SINGLE_STEP && r->step_fault_offset && c->Rip<=(DWORD64)(uintptr_t)(r->test+r->step_fault_offset)){c->Rip=(DWORD64)(uintptr_t)(r->test+r->step_fault_offset);c->EFlags|=saved_tf;return EXCEPTION_CONTINUE_EXECUTION;}
 if(r->stepping && code==EXCEPTION_SINGLE_STEP && r->steps_left>0 && c->Rip<(DWORD64)(uintptr_t)r->resume){r->steps_left--;c->EFlags|=saved_tf;return EXCEPTION_CONTINUE_EXECUTION;}
 /* The skip target is the exact end of the generated cell, not RIP+length:
    CC/CD03/F1 may already report the next address. */
 c->Rip=(DWORD64)(uintptr_t)r->resume;
 if(r->stopped)c->Rsp=u64(r->region+SNAP_OFFSET+9008);
 return EXCEPTION_CONTINUE_EXECUTION;
}
static int init_run(RUN*r){SYSTEM_INFO si;memset(r,0,sizeof(*r));GetSystemInfo(&si);r->page_size=si.dwPageSize;if(r->page_size!=PAGE_BYTES){r->skip="UNSUPPORTED_PAGE_SIZE";return 0;}r->region=(unsigned char*)VirtualAlloc(NULL,REGION_BYTES,MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE);if(!r->region){r->allocation_error=GetLastError();r->skip="ALLOCATION_FAILED";return 0;}r->traps=(TRAP*)calloc(TRACE_MAX,sizeof(TRAP));if(!r->traps){VirtualFree(r->region,0,MEM_RELEASE);r->region=NULL;r->skip="TRAP_BUFFER_ALLOCATION_FAILED";return 0;}r->code=r->region;r->data=r->region+DATA_OFFSET;r->before=(SNAP*)(r->region+SNAP_OFFSET);r->after=(SNAP*)(r->region+SNAP_OFFSET+4096);r->saved_fx=r->region+SNAP_OFFSET+8192;memset(r->data,0x5a,16*PAGE_BYTES);r->watch=r->data;return 1;}
static void free_run(RUN*r){free(r->traps);if(r->region)VirtualFree(r->region,0,MEM_RELEASE);}
static int finish_code(RUN*r){DWORD old;unsigned i;uint64_t *entry=(uint64_t*)(r->region+SNAP_OFFSET+9000),*safe=entry+1;
 /* Every nonvolatile GPR and FXSAVE image is restored before the C ABI resumes. */
 for(i=0;i<6;i++){b(r,0x8c);b(r,0x05|(i<<3));disp(r,r->region+SNAP_OFFSET+9040+i*2);}
 store(r,4,entry);b(r,0x9c);b(r,0x53);b(r,0x55);b(r,0x56);b(r,0x57);for(i=12;i<16;i++){b(r,0x41);b(r,0x50+(i&7));}store(r,4,safe);fx(r,0,r->saved_fx);for(i=0;i<32;i++){b(r,0x6a);b(r,0x00);}
 b(r,0xdb);b(r,0xe3); /* FNINIT */
 { unsigned mx=0x1f80; memcpy(r->region+SNAP_OFFSET+9024,&mx,4); b(r,0x0f);b(r,0xae);b(r,0x15);disp(r,r->region+SNAP_OFFSET+9024); }
 for(i=0;i<16;i++){b(r,0x66);if(i>=8)b(r,0x45);b(r,0x0f);b(r,0xef);b(r,0xc0|((i&7)<<3)|(i&7));}
 if(has_avx_setup){b(r,0xc5);b(r,0xfc);b(r,0x77);} /* VZEROALL after preserving caller FXSAVE */
 if(has_avx512_setup){for(i=0;i<4;i++){b(r,0x62);b(r,0xf1);b(r,0x7d-(i<<3));b(r,0x48);b(r,0xef);b(r,0xc0+(i<<3)+i);}for(i=0;i<8;i++){b(r,0xc5);b(r,0xfc-(i<<3));b(r,0x47);b(r,0xc0+(i<<3)+i);}}
 /* Canonical initial flags: IF is retained by user POPFQ; clear DF/TF/AC/NT. */
 b(r,0x68);d32(r,0x202);b(r,0x9d);
 if(has_avx_setup){memset(r->data+10*PAGE_BYTES+256,0xa5,32);mov_imm(r,0,(uint64_t)(uintptr_t)(r->data+10*PAGE_BYTES+256));b(r,0xc5);b(r,0x7c);b(r,0x10);b(r,0x38);}
 for(i=0;i<16;i++)if(i!=4)mov_imm(r,i,r->initial[i]);b(r,0x48);b(r,0x8d);b(r,0xac);b(r,0x24);d32(r,128); /* RBP = live synthetic stack + 128 */
 bytes(r,r->setup,r->setup_n);snapshot_code(r,r->before);if(r->arm_tf){b(r,0x68);d32(r,0x302);b(r,0x9d);}
 r->test=r->code+r->pc;bytes(r,r->instruction,r->instruction_n);r->instruction_length=r->instruction_n;r->resume=r->code+r->pc;
 snapshot_code(r,r->after);r->cleanup=r->code+r->pc;
 b(r,0x9c);b(r,0x48);b(r,0x81);b(r,0x24);b(r,0x24);d32(r,~(uint32_t)(0x100|0x400|0x40000|0x4000));b(r,0x9d);
 load(r,4,safe);fx(r,1,r->saved_fx);
 b(r,0x66);b(r,0x8b);b(r,0x05);disp(r,r->region+SNAP_OFFSET+9040+3*2);b(r,0x8e);b(r,0xd8);
 b(r,0x66);b(r,0x8b);b(r,0x05);disp(r,r->region+SNAP_OFFSET+9040);b(r,0x8e);b(r,0xc0);
 for(i=16;i-->12;){b(r,0x41);b(r,0x58+(i&7));}b(r,0x5f);b(r,0x5e);b(r,0x5d);b(r,0x5b);b(r,0x9d);b(r,0xc3);r->code_end=r->code+r->pc;
 if(r->code_error){r->skip="CODE_EMISSION_FAILED";return 0;}
 if(!VirtualProtect(r->code,CODE_BYTES,PAGE_EXECUTE_READ,&old)){r->protect_error=GetLastError();r->skip="EXECUTE_PROTECTION_FAILED";return 0;}
 if(!FlushInstructionCache(GetCurrentProcess(),r->code,r->pc)){r->protect_error=GetLastError();r->skip="FLUSH_INSTRUCTION_CACHE_FAILED";return 0;}
 return 1;
}
static void invoke(RUN*r){typedef void (*FN)(void);FN fn;void *p=r->code;memcpy(&fn,&p,sizeof(fn));r->owner_thread=GetCurrentThreadId();r->active=1;current=r;fn();r->active=0;current=NULL;r->entry_rsp=u64(r->region+SNAP_OFFSET+9000);r->safe_rsp=u64(r->region+SNAP_OFFSET+9008);}
static int protect_page(RUN*r,unsigned index,DWORD prot){DWORD old;if(!VirtualProtect(r->data+index*PAGE_BYTES,PAGE_BYTES,prot,&old)){r->protect_error=GetLastError();r->skip="DATA_PROTECTION_FAILED";return 0;}return 1;}
static void instruction(RUN*r,const unsigned char*p,size_t n){if(n>sizeof(r->instruction)){r->skip="INSTRUCTION_TOO_LONG_FOR_HARNESS";return;}memcpy(r->instruction,p,n);r->instruction_n=n;}
#define INS(r,...) do {const unsigned char ins_[]={__VA_ARGS__};instruction((r),ins_,sizeof(ins_));}while(0)
static void setup_bytes(RUN*r,const unsigned char*p,size_t n){if(r->setup_n+n>sizeof(r->setup)){r->skip="SETUP_TOO_LONG";return;}memcpy(r->setup+r->setup_n,p,n);r->setup_n+=n;}
#define SETUP(r,...) do {const unsigned char s_[]={__VA_ARGS__};setup_bytes((r),s_,sizeof(s_));}while(0)
static void common_inputs(RUN*r){unsigned i;for(i=0;i<16;i++)r->initial[i]=UINT64_C(0x1111000000000000)+i*0x101;r->initial[0]=0;r->initial[1]=0;r->initial[2]=0;r->initial[3]=(uint64_t)(uintptr_t)r->data;r->initial[5]=(uint64_t)(uintptr_t)(r->data+2048);r->initial[6]=(uint64_t)(uintptr_t)(r->data+8*PAGE_BYTES);r->initial[7]=(uint64_t)(uintptr_t)(r->data+9*PAGE_BYTES);}
static void print_traps(RUN*r){unsigned i,j;append(" traps=%u vector=NA error_code=NA",r->trap_count);for(i=0;i<r->trap_count&&i<TRACE_MAX;i++){EXCEPTION_RECORD*e=&r->traps[i].record;char tag[32];append(" ex%u.code=%08lx ex%u.flags=%08lx ex%u.record=",i,(unsigned long)e->ExceptionCode,i,(unsigned long)e->ExceptionFlags,i);address(r,(uint64_t)(uintptr_t)e->ExceptionRecord);append(" ex%u.address=",i);address(r,(uint64_t)(uintptr_t)e->ExceptionAddress);append(" ex%u.address_raw=%016llx ex%u.parameters=%lu",i,(unsigned long long)(uintptr_t)e->ExceptionAddress,i,(unsigned long)e->NumberParameters);for(j=0;j<e->NumberParameters&&j<EXCEPTION_MAXIMUM_PARAMETERS;j++){append(" ex%u.param%u=",i,j);address(r,(uint64_t)e->ExceptionInformation[j]);append(" ex%u.param%u_raw=%016llx",i,j,(unsigned long long)e->ExceptionInformation[j]);}sprintf(tag,"trap%u",i);context_out(r,tag,&r->traps[i].context);append(" %s.raw=",tag);rawhex((const unsigned char*)&r->traps[i].context,sizeof(CONTEXT));{EXTENDED*e=&r->traps[i].extended;static const unsigned ids[]={2,5,6,7};append(" %s.exact_xstate_status=%u %s.exact_xstate_mask=%016llx",tag,e->status,tag,(unsigned long long)e->mask);for(j=0;j<4;j++){append(" %s.xstate%u_length=%lu %s.xstate%u=",tag,ids[j],(unsigned long)e->length[j],tag,ids[j]);rawhex(e->feature[j],e->length[j]);}}} }
static DWORD WINAPI context_thread(void *p){HANDLE e=(HANDLE)p;WaitForSingleObject(e,INFINITE);return 0;}
static void capture_context_cell(int other){ALIGN16 CONTEXT c;HANDLE event=NULL,thread=NULL;DWORD tid=0,suspend_count,err=0,resume_count,join_status;BOOL got;memset(&c,0,sizeof(c));
 if(!other){RtlCaptureContext(&c);append(" status=OK source=RtlCaptureContext");context_out(NULL,"context",&c);append(" context.raw=");rawhex((const unsigned char*)&c,sizeof(c));return;}
 event=CreateEventW(NULL,TRUE,FALSE,NULL);if(!event){append(" status=API_ERROR api=CreateEventW error=%lu",(unsigned long)GetLastError());return;}
 thread=CreateThread(NULL,0,context_thread,event,0,&tid);if(!thread){err=GetLastError();CloseHandle(event);append(" status=API_ERROR api=CreateThread error=%lu",(unsigned long)err);return;}
 suspend_count=SuspendThread(thread);if(suspend_count==(DWORD)-1){err=GetLastError();SetEvent(event);WaitForSingleObject(thread,5000);CloseHandle(thread);CloseHandle(event);append(" status=API_ERROR api=SuspendThread error=%lu",(unsigned long)err);return;}
 c.ContextFlags=CONTEXT_ALL;got=GetThreadContext(thread,&c);if(!got)err=GetLastError();resume_count=ResumeThread(thread);if(resume_count==(DWORD)-1&&!err)err=GetLastError();if(!SetEvent(event)&&!err)err=GetLastError();join_status=WaitForSingleObject(thread,5000);if(join_status!=WAIT_OBJECT_0&&!err)err=join_status==WAIT_FAILED?GetLastError():join_status;CloseHandle(thread);CloseHandle(event);
 append(" status=%s source=GetThreadContext requested_flags=%08lx suspend_previous=%lu resume_previous=%lu error=%lu",got&&!err?"OK":"API_ERROR",(unsigned long)CONTEXT_ALL,(unsigned long)suspend_count,(unsigned long)resume_count,(unsigned long)err);if(got){context_out(NULL,"context",&c);append(" context.raw=");rawhex((const unsigned char*)&c,sizeof(c));}
}
static size_t fromhex(unsigned char *outbuf,size_t cap,const char*s){size_t n=0;unsigned v;while(*s){while(*s==' ')s++;if(!*s)break;if(sscanf(s,"%2x",&v)!=1||n==cap)return 0;outbuf[n++]=(unsigned char)v;s+=2;}return n;}
static int read_base(unsigned which,uint64_t*v){RUN r;int ok=0;if(!init_run(&r))return 0;common_inputs(&r);if(which)INS(&r,0xf3,0x48,0x0f,0xae,0xc8);else INS(&r,0xf3,0x48,0x0f,0xae,0xc0);if(finish_code(&r)){invoke(&r);if(r.trap_count==0){*v=r.after->gpr[0];ok=1;}}free_run(&r);return ok;}
static uint16_t selector(unsigned i){ALIGN16 CONTEXT c;memset(&c,0,sizeof c);RtlCaptureContext(&c);switch(i){case 0:return c.SegCs;case 1:return c.SegSs;case 2:return c.SegDs;case 3:return c.SegEs;case 4:return c.SegFs;case 5:return c.SegGs;case 6:return 0;case 7:return 0xffff;case 8:return 8;default:return 4;}}
static int query_instruction(const unsigned char *p,size_t n,uint64_t a,uint64_t b,uint64_t *ra,uint64_t *rb,uint64_t *rc,uint64_t *rd){RUN r;int ok=0;if(!init_run(&r))return 0;common_inputs(&r);r.initial[0]=a;r.initial[1]=b;instruction(&r,p,n);if(finish_code(&r)){invoke(&r);if(!r.trap_count){*ra=r.after->gpr[0];*rb=r.after->gpr[3];*rc=r.after->gpr[1];*rd=r.after->gpr[2];ok=1;}}free_run(&r);return ok;}
static int supports_vector(unsigned avx512){const unsigned char cp[]={0x0f,0xa2},xg[]={0x0f,0x01,0xd0};uint64_t a,b,c,d,xcr;if(!query_instruction(cp,2,1,0,&a,&b,&c,&d)||(!(c&(1u<<27))||!(c&(1u<<28))))return 0;if(!query_instruction(xg,3,0,0,&a,&b,&c,&d))return 0;xcr=a|(d<<32);if((xcr&6)!=6)return 0;if(avx512==2)return 1;if(!query_instruction(cp,2,7,0,&a,&b,&c,&d))return 0;return avx512?((b&(1u<<16))&&(xcr&0xe6)==0xe6):!!(b&(1u<<5));}
static uint64_t win_xcr0;
static int win_cp(unsigned leaf,unsigned sub,unsigned v[4]){const unsigned char p[]={0x0f,0xa2};uint64_t a,b,c,d;if(!query_instruction(p,2,leaf,sub,&a,&b,&c,&d))return 0;v[0]=(unsigned)a;v[1]=(unsigned)b;v[2]=(unsigned)c;v[3]=(unsigned)d;return 1;}
static int win_bit(unsigned leaf,unsigned sub,unsigned reg,unsigned bitn){unsigned v[4];if(!win_cp(leaf,sub,v))return -1;return (v[reg]>>bitn)&1;}
static void init_machine(void){unsigned v[4]={0,0,0,0};const unsigned char xg[]={0x0f,0x01,0xd0};uint64_t a,b,c,d;if(win_cp(1,0,v)&&(v[2]&(1u<<27))&&query_instruction(xg,3,0,0,&a,&b,&c,&d))win_xcr0=(d<<32)|(uint32_t)a;
 {const unsigned char vx[]={0xc5,0xfc,0x57,0xc0},vz[]={0x62,0xf1,0x7d,0x48,0xef,0xc0};if((win_xcr0&6)==6&&(v[2]&(1u<<28))&&query_instruction(vx,sizeof vx,0,0,&a,&b,&c,&d))has_avx_setup=1;if(has_avx_setup&&(win_xcr0&0xe6)==0xe6&&win_cp(7,0,v)&&(v[1]&(1u<<16))&&query_instruction(vz,sizeof vz,0,0,&a,&b,&c,&d))has_avx512_setup=1;}}

static int win_gate_bit(const char *g){
 #define G(N,L,S,R,B) if(!strcmp(g,N))return win_bit(L,S,R,B)
 G("sse3",1,0,2,0);G("ssse3",1,0,2,9);G("sse41",1,0,2,19);G("sse42",1,0,2,20);G("avx",1,0,2,28);G("fma",1,0,2,12);G("f16c",1,0,2,29);G("avx2",7,0,1,5);
 G("avx512bf16",7,1,0,5);G("avx512fp16",7,0,3,23);G("avx512vp2intersect",7,0,3,8);G("avx512er",7,0,1,27);G("avx5124vnniw",7,0,3,2);G("avx5124fmaps",7,0,3,3);G("avx512pf",7,0,1,26);G("avx512f",7,0,1,16);G("avx512dq",7,0,1,17);G("avx512ifma",7,0,1,21);G("avx512cd",7,0,1,28);G("avx512bw",7,0,1,30);G("avx512vl",7,0,1,31);G("avx512vbmi",7,0,2,1);G("avx512vbmi2",7,0,2,6);G("avx512vnni",7,0,2,11);G("avx512bitalg",7,0,2,12);G("avx512vpopcntdq",7,0,2,14);
 G("avx512bf16",7,1,0,5);G("avx512fp16",7,0,3,23);G("avx512vp2intersect",7,0,3,8);G("avx512er",7,0,1,27);G("avx5124vnniw",7,0,3,2);G("avx5124fmaps",7,0,3,3);G("avx512pf",7,0,1,26);
 G("bmi1",7,0,1,3);G("bmi2",7,0,1,8);G("adx",7,0,1,19);G("popcnt",1,0,2,23);G("lzcnt",0x80000001u,0,2,5);G("movbe",1,0,2,22);G("rdrand",1,0,2,30);G("rdseed",7,0,1,18);G("sha",7,0,1,29);G("aes",1,0,2,25);G("pclmul",1,0,2,1);G("vaes",7,0,2,9);G("vpclmul",7,0,2,10);G("gfni",7,0,2,8);G("clflushopt",7,0,1,23);G("clwb",7,0,1,24);G("fsgsbase",7,0,1,0);G("cx16",1,0,2,13);G("lahf64",0x80000001u,0,2,0);G("prefetchw",0x80000001u,0,2,8);G("fxsr",1,0,3,24);G("osxsave",1,0,2,27);G("xsaveopt",13,1,0,0);G("xsavec",13,1,0,1);G("xgetbv1",13,1,0,2);G("serialize",7,0,3,14);G("rdpid",7,0,2,22);G("rdtscp",0x80000001u,0,3,27);G("tsc",1,0,3,4);
 #undef G
 return -1;
}
static int win_gate_os(const char *g){if(!strncmp(g,"avx512",6))return (win_xcr0&0xe6)==0xe6;if(!strcmp(g,"avx")||!strcmp(g,"avx2")||!strcmp(g,"fma")||!strcmp(g,"f16c")||!strcmp(g,"vaes")||!strcmp(g,"vpclmul"))return (win_xcr0&6)==6;if(!strncmp(g,"xsave",5)||!strcmp(g,"xgetbv1")||!strcmp(g,"osxsave"))return win_bit(1,0,2,27);return 1;}
static void configure(RUN*r,const Cell*c){const char*n=c->name;unsigned bit;uint64_t value;common_inputs(r);r->kind=n;r->instruction_n=fromhex(r->instruction,sizeof r->instruction,c->hex);
 if(c->gate && !strncmp(c->gate,"SKIP_",5)){r->skip=c->gate;return;}
 switch(c->kind){
 case K_CPUID:r->initial[0]=c->a;r->initial[1]=c->b;break;
 case K_XGETBV:r->initial[1]=c->a;break;
 case K_FEATURE:
  if((!strncmp(c->gate,"avx",3)||!strncmp(c->gate,"xsave",5)||!strcmp(c->gate,"osxsave")||!strcmp(c->gate,"vaes")||!strcmp(c->gate,"vpclmul")||!strcmp(c->gate,"fma")||!strcmp(c->gate,"f16c"))&&!win_gate_os(c->gate)){r->skip="SKIP_FEATURE_OS_VECTOR_STATE_DISABLED";return;}
  r->initial[3]=(uint64_t)(uintptr_t)r->data;
  if(strstr(n,"wrfsbase_same")||strstr(n,"wrgsbase_same")){if(!read_base(strstr(n,"wrgsbase")!=NULL,&value)){r->skip="SKIP_PREREQUISITE_BASE_READ_FAULT";return;}r->initial[0]=value;}
  if(strstr(n,"xsave")){unsigned v[4];if(win_cp(13,0,v)&&v[1]>16*PAGE_BYTES){r->skip="UNIMPLEMENTED_XSAVE_AREA_ABOVE_64K";return;}r->initial[0]=(uint32_t)win_xcr0;r->initial[2]=win_xcr0>>32;memset(r->data,0,16*PAGE_BYTES);}else if(strstr(n,"fxsave"))memset(r->data,0,16*PAGE_BYTES);
  break;
 case K_SEGREAD:r->initial[3]=(uint64_t)(uintptr_t)r->data;break;
 case K_SELECTOR:r->initial[3]=selector(c->b);break;
 case K_SEGLOAD:
  if(c->a==2||c->a==3){r->skip="SKIP_SAFETY_TLS_SELECTOR";return;}
  r->initial[0]=c->b==0?0:c->b==2?0xffff:selector(c->a==0?2:c->a==1?3:1);break;
 case K_FLAGS:
  if(c->a==1){bit=c->b;value=UINT64_C(0x202)^(UINT64_C(1)<<bit);r->initial[0]=value;SETUP(r,0x50);INS(r,0x9d,0x90);}
  else if(c->a==3){static const unsigned pat[]={0,255,85,170};r->initial[0]=(uint64_t)pat[c->b]<<8;}
  break;
 case K_TRAP:
  if(c->a==1&&c->b==0x29){r->skip="SKIP_OS_FASTFAIL";return;}
  if(c->a==1&&c->b==0x2d){r->skip="UNIMPLEMENTED_WINDOWS_INT2D_DISPATCH";return;}
  if(c->a==1&&(c->b==0x2e||c->b==0x80)){r->skip="SKIP_SYSCALL";return;}
  if(strstr(n,"noncanonical_stack")){r->skip="UNIMPLEMENTED_INVALID_RSP_VEH_DISPATCH";return;}
  if(strstr(n,"noncanonical_data")||strstr(n,"noncanonical_jump")||strstr(n,"noncanonical_return")){r->initial[0]=UINT64_C(0x0100000000000000);if(strstr(n,"return"))SETUP(r,0x50);}
  if(strstr(n,"misaligned"))r->initial[3]=(uint64_t)(uintptr_t)(r->data+1);
  if(strstr(n,"div_zero")){r->initial[0]=0;r->initial[2]=0;r->initial[3]=0;}
  if(strstr(n,"div_overflow")){r->initial[0]=0;r->initial[2]=1;r->initial[3]=1;}
  if(strstr(n,"x87_deferred")){unsigned short cw=0x037b;memcpy(r->data,&cw,2);r->initial[3]=(uint64_t)(uintptr_t)r->data;SETUP(r,0xd9,0x2b);/* FLDCW [rbx] */}
  if(strstr(n,"sse_unmasked")){uint32_t mx=0x1f00;memcpy(r->data,&mx,4);r->initial[3]=(uint64_t)(uintptr_t)r->data;SETUP(r,0x0f,0xae,0x13);}
  break;
 case K_PREFIX:{static const unsigned char pref[][6]={{0x66,0x66,0,0,0,0},{0xf2,0xf3,0,0,0,0},{0xf3,0xf2,0,0,0,0},{0x48,0x66,0,0,0,0},{0x66,0x48,0,0,0,0},{0x40,0x48,0,0,0,0},{0xf3,0x66,0x48,0,0,0},{0x48,0xf3,0x66,0,0,0}};static const unsigned lens[]={2,2,2,2,2,2,3,3};unsigned k=lens[c->b];memmove(r->instruction+k,r->instruction,r->instruction_n);memcpy(r->instruction,pref[c->b],k);r->instruction_n+=k;if(c->a==16)r->ret_zero_target=1;break;}
 case K_MEMORY:
  switch(c->a){
  case 0:case 1:case 12:case 13:r->skip="UNIMPLEMENTED_INVALID_RSP_VEH_DISPATCH";return;
  case 2:r->initial[3]=(uint64_t)(uintptr_t)(r->data+PAGE_BYTES);protect_page(r,1,PAGE_NOACCESS);INS(r,0x8f,0x03);break;
  case 3:case 4:case 5:case 6:
   r->initial[1]=8;r->initial[6]=(uint64_t)(uintptr_t)(r->data+2*PAGE_BYTES-4);r->initial[7]=(uint64_t)(uintptr_t)(r->data+4*PAGE_BYTES-4);r->watch=r->data+4*PAGE_BYTES-128;
   protect_page(r,2,PAGE_NOACCESS);protect_page(r,4,PAGE_NOACCESS);
   if(c->a==3){memset(r->data+2*PAGE_BYTES-4,0xa5,4);INS(r,0xf3,0xa4);}if(c->a==4)INS(r,0xf3,0xaa);if(c->a==5)INS(r,0xf3,0xa6);if(c->a==6){r->initial[0]=0x5a;INS(r,0xf3,0xae);}break;
  case 7:case 8:case 9:case 10:case 11:
   r->initial[3]=(uint64_t)(uintptr_t)(r->data+6*PAGE_BYTES);r->initial[0]=c->a==9?0:UINT64_C(0x5a5a5a5a5a5a5a5a);r->watch=r->data+6*PAGE_BYTES;protect_page(r,6,PAGE_READONLY);
   if(c->a==7)INS(r,0x48,0x87,0x03);if(c->a==8||c->a==9)INS(r,0x48,0x0f,0xb1,0x0b);if(c->a==10)INS(r,0x48,0x0f,0xc1,0x03);if(c->a==11)INS(r,0x48,0x01,0x03);break;
  case 14:r->initial[3]=(uint64_t)(uintptr_t)(r->data+2*PAGE_BYTES-4);INS(r,0x48,0x89,0x03);break;
  case 15:memset(r->data+8*PAGE_BYTES,0xa5,8);r->initial[1]=8;r->initial[6]=(uint64_t)(uintptr_t)(r->data+8*PAGE_BYTES);r->initial[7]=(uint64_t)(uintptr_t)(r->data+2*PAGE_BYTES-4);INS(r,0xf3,0xa4);break;
  case 16:r->initial[3]=(uint64_t)(uintptr_t)(r->data+2*PAGE_BYTES-8);INS(r,0x0f,0x11,0x03);break;
  case 17:case 18:
   if(!supports_vector(2)){r->skip="SKIP_PREREQUISITE_AVX_XSTATE";return;}r->initial[3]=(uint64_t)(uintptr_t)(r->data+2*PAGE_BYTES-16);SETUP(r,0xc5,0xfc,0x57,0xc0,0xc5,0xf4,0x57,0xc9);if(c->a==17)INS(r,0xc5,0xfc,0x11,0x03);else INS(r,0xc4,0xe2,0x7d,0x2e,0x03);break;
  case 19:if(!supports_vector(1)){r->skip="SKIP_PREREQUISITE_AVX512F_XSTATE";return;}r->xsave_mask=0xe7;r->initial[3]=(uint64_t)(uintptr_t)(r->data+2*PAGE_BYTES-32);SETUP(r,0x62,0xf1,0x7d,0x48,0xef,0xc0,0xc5,0xf4,0x47,0xc9);INS(r,0x62,0xf1,0x7c,0x49,0x11,0x03);break;
  case 20:{uint32_t indexes[8]={0,1,2,3,4,5,6,7};if(!supports_vector(0)){r->skip="SKIP_PREREQUISITE_AVX2_XSTATE";return;}r->xsave_mask=7;memcpy(r->data+128,indexes,sizeof indexes);r->initial[3]=(uint64_t)(uintptr_t)(r->data+2*PAGE_BYTES-16);r->initial[7]=(uint64_t)(uintptr_t)(r->data+128);SETUP(r,0xc5,0xfd,0xef,0xc0,0xc5,0xfe,0x6f,0x0f,0xc5,0xed,0x76,0xd2);INS(r,0xc4,0xe2,0x6d,0x92,0x04,0x8b);break;}
  default:r->skip="UNIMPLEMENTED_MEMORY_AXIS";return;
  }if(c->a>=14){protect_page(r,2,PAGE_NOACCESS);r->watch=r->data+2*PAGE_BYTES-128;}break;
 case K_STEP:
  r->stepping=1;r->steps_left=16;r->arm_tf=c->a!=1;
  switch(c->a){
   case 0:INS(r,0x90,0x90);break;
   case 1:SETUP(r,0x68,0x02,0x03,0,0);INS(r,0x9d,0x90,0x90);break;
   case 2:INS(r,0x9c,0x58,0x90);break;
   case 3:r->initial[0]=selector(1);INS(r,0x8e,0xd0,0x90,0x90);break;
   case 4:INS(r,0x17,0x90);r->step_fault_offset=1;break;
   case 5:r->initial[1]=4;INS(r,0xf3,0xa4,0x90);break;
   case 6:INS(r,0x0f,0xa2,0x90);break;
   case 7:INS(r,0x0f,0x31,0x90);break;
   case 8:r->skip="SKIP_SYSCALL";return;
   case 9:INS(r,0xcc,0x90);r->step_fault_offset=1;break;
   case 10:INS(r,0xcd,0x03,0x90);r->step_fault_offset=2;break;
   case 11:r->initial[3]=(uint64_t)(uintptr_t)(r->data+2*PAGE_BYTES);protect_page(r,2,PAGE_NOACCESS);INS(r,0x48,0x8b,0x03,0x90);r->step_fault_offset=3;break;
   case 12:SETUP(r,0x68,0x02,0x02,0,0);INS(r,0x9d,0x90,0x90);break;
  }break;
 case K_TIMING:r->skip="TIMING_SEPARATE";return;
 default:r->skip="UNIMPLEMENTED_KIND";return;
 }
 if(!r->instruction_n&&!r->skip)r->skip="UNIMPLEMENTED_INSTRUCTION";
}
static PVOID veh_handle,veh_gate;
static int isolation_abort;
static int install_handler(void){unsigned char *p;size_t n=0;DWORD old;uintptr_t target=(uintptr_t)(void*)veh;PVECTORED_EXCEPTION_HANDLER handler;
 {HMODULE k=GetModuleHandleW(L"kernel32.dll");if(k){get_xmask=(GET_XMASK)GetProcAddress(k,"GetXStateFeaturesMask");locate_xstate=(LOCATE_XSTATE)GetProcAddress(k,"LocateXStateFeature");}}
 p=(unsigned char*)VirtualAlloc(NULL,PAGE_BYTES,MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE);if(!p)return 0;
 /* Clear flags before entering any compiler-generated handler code or Win32 API.
    This does not change the exception CONTEXT image supplied by the OS. */
 p[n++]=0x9c;p[n++]=0x48;p[n++]=0x81;p[n++]=0x24;p[n++]=0x24;{uint32_t mask=~(uint32_t)(0x100|0x400|0x40000|0x4000);memcpy(p+n,&mask,4);n+=4;}p[n++]=0x9d;p[n++]=0x48;p[n++]=0xb8;memcpy(p+n,&target,8);n+=8;p[n++]=0xff;p[n++]=0xe0;
 if(!VirtualProtect(p,PAGE_BYTES,PAGE_EXECUTE_READ,&old)||!FlushInstructionCache(GetCurrentProcess(),p,n)){VirtualFree(p,0,MEM_RELEASE);return 0;}memcpy(&handler,&p,sizeof(handler));veh_handle=AddVectoredExceptionHandler(1,handler);if(!veh_handle){VirtualFree(p,0,MEM_RELEASE);return 0;}veh_gate=p;return 1;
}
static void remove_handler(void){if(veh_handle)RemoveVectoredExceptionHandler(veh_handle);if(veh_gate)VirtualFree(veh_gate,0,MEM_RELEASE);}
static void run_cell(unsigned id){const Cell*c=&cells[id];RUN r;unsigned char memory_before[128];
 out_n=0;append("CELL %u %s =>",id,c->name);
 if(c->kind==K_TIMING){append(" status=TIMING_SEPARATE source=windows_probe.exe_timing_JSON axis=%u bitwise_excluded=1",c->a);emit_line();return;}
 if(c->kind==K_WINDOWS){capture_context_cell(c->a==0);emit_line();return;}
 if(!init_run(&r)){append(" status=%s winerror=%lu",r.skip?r.skip:"ALLOCATION_FAILED",(unsigned long)r.allocation_error);emit_line();return;}
 configure(&r,c);
 if(r.skip){append(" status=%s",r.skip);if(r.protect_error)append(" winerror=%lu",(unsigned long)r.protect_error);emit_line();free_run(&r);return;}
 memcpy(memory_before,r.watch,128);
 if(!finish_code(&r)){append(" status=%s winerror=%lu",r.skip?r.skip:"CODE_ERROR",(unsigned long)r.protect_error);emit_line();free_run(&r);return;}
 invoke(&r);append(" status=%s instruction=",r.trap_count?"TRAP":"OK");rawhex(r.instruction,r.instruction_n);if(r.ret_zero_target)append(" control_transfer_target=0x0 control_transfer_input=zero_filled_stack");append(" length=%u resume=instruction_end handler_policy=%s",(unsigned)r.instruction_length,r.stepping?"preserve_saved_TF_skip_fault_to_NOP":"skip_to_instruction_end_clear_TF_DF_AC");
 append(" requested_start_TF=%u before_capture=pre_TF_arm effective_start_flags_constructed=0x%016llx instruction_address=",r.arm_tf,(unsigned long long)(r.arm_tf?(r.before->flags|0x100):r.before->flags));address(&r,(uint64_t)(uintptr_t)r.test);append(" continuation_address=");address(&r,(uint64_t)(uintptr_t)r.resume);snapshot_out(&r,"before",r.before);
 if(c->kind==K_CPUID)append(" leaf=0x%08x subleaf=0x%08x eax=0x%08x ebx=0x%08x ecx=0x%08x edx=0x%08x",c->a,c->b,(unsigned)r.after->gpr[0],(unsigned)r.after->gpr[3],(unsigned)r.after->gpr[1],(unsigned)r.after->gpr[2]);
 if(c->kind==K_XGETBV)append(" index=0x%x value=0x%016llx",c->a,(unsigned long long)((r.after->gpr[2]<<32)|(uint32_t)r.after->gpr[0]));
 if(c->kind==K_FEATURE)append(" gate=%s cpuid_bit=0x%x os_enabled=0x%x operands_valid=0x1",c->gate,win_gate_bit(c->gate),win_gate_os(c->gate));
 if(c->kind==K_FLAGS&&c->a==1)append(" bit=0x%x attempted=0x%016llx",c->b,(unsigned long long)(UINT64_C(0x202)^(UINT64_C(1)<<c->b)));
 snapshot_out(&r,"continued",r.after);print_traps(&r);
 append(" memory_watch_offset=%llu memory_before=",(unsigned long long)(r.watch-r.data));rawhex(memory_before,sizeof memory_before);append(" memory_after=");rawhex(r.watch,128);
 if(c->kind==K_FEATURE&&(strstr(c->name,"xsave")||strstr(c->name,"fxsave"))){append(" save_area_first_1024=");rawhex(r.data,1024);{unsigned cpv[4]={0,0,0,0};win_cp(13,0,cpv);append(" required_bytes=0x%x mxcsr_mask=0x%08x fx_fcw=0x%04x fx_fsw=0x%04x fx_ftw=0x%02x fx_fop=0x%04x fx_fip=0x%016llx fx_fdp=0x%016llx",cpv[1],u32(r.data+28),u16(r.data),u16(r.data+2),r.data[4],u16(r.data+6),(unsigned long long)u64(r.data+8),(unsigned long long)u64(r.data+16));}append(" xstate_bv=0x%016llx xcomp_bv=0x%016llx request_mask=0x%016llx header_zeroed=0x1 allocated=0x10000",(unsigned long long)u64(r.data+512),(unsigned long long)u64(r.data+520),(unsigned long long)win_xcr0);}
 if(r.xsave_mask){append(" capture_xsave_mask=%x before_xsave=",r.xsave_mask);rawhex(r.region+196608,4096);append(" continued_xsave=");rawhex(r.region+212992,4096);}
 emit_line();free_run(&r);
}

/* Risky cells run in a fresh copy of this exact executable. No debugger,
 * unrelated process, or shell is involved. The parent owns the timeout. */
static void isolated_cell(unsigned id){
 HANDLE rd=NULL,wr=NULL;SECURITY_ATTRIBUTES sa;STARTUPINFOW si;PROCESS_INFORMATION pi;
 wchar_t *path=NULL,*cmd=NULL;char *capture=NULL;size_t used=0;DWORD n,available,got,exit_code=0,create_error=0;ULONGLONG started;int timeout=0,io_error=0,launched=0;char expected[48];
 memset(&sa,0,sizeof sa);sa.nLength=sizeof sa;sa.bInheritHandle=TRUE;memset(&si,0,sizeof si);si.cb=sizeof si;memset(&pi,0,sizeof pi);
 path=(wchar_t*)calloc(32768,sizeof(wchar_t));cmd=(wchar_t*)calloc(32832,sizeof(wchar_t));capture=(char*)malloc(LINE_CAP);
 if(!path||!cmd||!capture){create_error=ERROR_NOT_ENOUGH_MEMORY;goto done;}
 n=GetModuleFileNameW(NULL,path,32768);if(!n||n>=32768){create_error=GetLastError();goto done;}
 if(swprintf(cmd,32832,L"\"%ls\" --worker %u",path,id)<0){create_error=ERROR_INSUFFICIENT_BUFFER;goto done;}
 if(!CreatePipe(&rd,&wr,&sa,0)){create_error=GetLastError();goto done;}
 if(!SetHandleInformation(rd,HANDLE_FLAG_INHERIT,0)){create_error=GetLastError();goto done;}
 si.dwFlags=STARTF_USESTDHANDLES;si.hStdOutput=wr;si.hStdError=wr;si.hStdInput=GetStdHandle(STD_INPUT_HANDLE);
 if(!CreateProcessW(path,cmd,NULL,NULL,TRUE,CREATE_NO_WINDOW,NULL,NULL,&si,&pi)){create_error=GetLastError();goto done;}
 launched=1;CloseHandle(wr);wr=NULL;started=GetTickCount64();
 for(;;){
  available=0;if(!PeekNamedPipe(rd,NULL,0,NULL,&available,NULL)){DWORD e=GetLastError();if(e!=ERROR_BROKEN_PIPE)io_error=1;break;}
  if(available){DWORD take=available;if(used+take>=LINE_CAP){io_error=2;break;}if(!ReadFile(rd,capture+used,take,&got,NULL)){io_error=1;break;}used+=got;}
  if(WaitForSingleObject(pi.hProcess,0)==WAIT_OBJECT_0){if(!available)break;}
  if(GetTickCount64()-started>=10000){timeout=1;break;}Sleep(1);
 }
 if(!timeout&&!io_error&&WaitForSingleObject(pi.hProcess,0)!=WAIT_OBJECT_0){ULONGLONG elapsed=GetTickCount64()-started;if(elapsed>=10000||WaitForSingleObject(pi.hProcess,(DWORD)(10000-elapsed))!=WAIT_OBJECT_0)timeout=1;}
 if(timeout||io_error){BOOL killed=TerminateProcess(pi.hProcess,0x00860001);DWORD kill_error=killed?0:GetLastError();DWORD waited=WaitForSingleObject(pi.hProcess,5000);if(waited!=WAIT_OBJECT_0){isolation_abort=1;io_error=3;create_error=kill_error?kill_error:(waited==WAIT_FAILED?GetLastError():waited);}}
 if(!GetExitCodeProcess(pi.hProcess,&exit_code))io_error=1;
 done:
 if(wr)CloseHandle(wr);if(rd)CloseHandle(rd);if(launched){CloseHandle(pi.hThread);CloseHandle(pi.hProcess);}
 out_n=0;snprintf(expected,sizeof expected,"CELL %u ",id);
 if(launched&&!timeout&&!io_error&&!exit_code&&used){
  while(used&&(capture[used-1]=='\n'||capture[used-1]=='\r'))used--;capture[used]=0;
  if(!strncmp(capture,expected,strlen(expected))&&!strchr(capture,'\n')){append("%s",capture);emit_line();goto release;}
 }
 append("CELL %u %s => status=%s child_exit=0x%08lx winerror=%lu exact_trap_state=UNAVAILABLE",id,cells[id].name,!launched?"ERROR_CHILD_CREATE":isolation_abort?"ERROR_CHILD_CLEANUP":timeout?"ERROR_CHILD_TIMEOUT":io_error?"ERROR_CHILD_IO":"ERROR_CHILD_TERMINATION",(unsigned long)exit_code,(unsigned long)create_error);
 if(used){append(" child_diagnostic_hex=");rawhex((const unsigned char*)capture,used<2048?used:2048);}emit_line();
 release:free(path);free(cmd);free(capture);
}

/* WINDOWS_B7_TIMING_BEGIN
 * 0086 B7 Windows x64 source-only implementation, included textually in the
 * single-file windows_probe.c. No Windows build or execution during preparation.
 * Uses only owned memory, a private event, owned-thread affinity, a scoped VEH,
 * and documented Win32 APIs. No numeric native syscall, scheduler elevation,
 * other-process state, registry, network, or privileged instruction.
 */
#define W86_SAMPLES 10000u
#define W86_MONO_READS 20000u
#define W86_WARMUP 128u
#define W86_CLOCK_INTERVALS 5u
#ifndef EXCEPTION_SOFTWARE_ORIGINATE
#define EXCEPTION_SOFTWARE_ORIGINATE 0x80u
#endif
#define W86_EXCEPTION_CODE ((DWORD)0xe0860001u)
#define W86_CODE_BYTES 4096u

typedef struct { uint64_t tsc; uint32_t aux, reserved; } W86_STAMP;
typedef char W86_STAMP_LAYOUT[(sizeof(W86_STAMP)==16&&offsetof(W86_STAMP,aux)==8)?1:-1];
typedef struct { unsigned char *entry, *fault_begin, *recover; size_t size; } W86_FN;
typedef struct {
 unsigned char *code; size_t used; int code_error;
 W86_FN raw[2], ordered[2], pair[2], cpuid, loop;
 W86_FN *volatile active_fn; DWORD owner;
 volatile DWORD fault_code; volatile LONG raising, deliveries;
 HANDLE event; PVOID handler; int lfence;
} W86_RUN;
typedef struct {
 uint64_t value[W86_SAMPLES]; unsigned attempted,valid,backwards,migrated,failed;
 DWORD instruction_fault;
} W86_DISTRIBUTION;
static W86_RUN *volatile w86_active;

static const char *w86_bool(int v){return v?"true":"false";}
static void w86_json_string(FILE *f,const char *s){const unsigned char *p=(const unsigned char*)s;fputc('"',f);for(;*p;p++){if(*p=='"'||*p=='\\'){fputc('\\',f);fputc(*p,f);}else if(*p<32||*p>126)fprintf(f,"\\u%04x",*p);else fputc(*p,f);}fputc('"',f);}
static int w86_cmp(const void *aa,const void *bb){uint64_t a=*(const uint64_t*)aa,b=*(const uint64_t*)bb;return (a>b)-(a<b);}
static void w86_emit_distribution(FILE *f,W86_DISTRIBUTION *d){
 fprintf(f,"{\"requested\":%u,\"attempted\":%u,\"valid\":%u,\"backwards\":%u,\"migrated\":%u,\"workload_failed\":%u,\"instruction_fault\":%lu,",W86_SAMPLES,d->attempted,d->valid,d->backwards,d->migrated,d->failed,(unsigned long)d->instruction_fault);
 if(d->valid){unsigned n=d->valid,p99=(99u*n+99u)/100u-1u;double median;qsort(d->value,n,sizeof d->value[0],w86_cmp);median=(n&1u)?(double)d->value[n/2]:(double)d->value[n/2-1]/2.0+(double)d->value[n/2]/2.0;fprintf(f,"\"min_ticks\":%" PRIu64 ",\"median_ticks\":%.1f,\"p99_ticks\":%" PRIu64 ",\"max_ticks\":%" PRIu64 "}",d->value[0],median,d->value[p99],d->value[n-1]);}
 else fputs("\"min_ticks\":null,\"median_ticks\":null,\"p99_ticks\":null,\"max_ticks\":null}",f);
}
/* Byte emission is audited without executing this Windows code on Linux.
 * Every helper saves RBX before its catchable range and has POP RBX;RET as
 * recovery. The helpers never modify RSP again, call another function, or use
 * nonvolatile SIMD registers. RCX (output pointer) is retained in volatile R8. */
static void w86_b(W86_RUN *r,unsigned x){if(r->used>=W86_CODE_BYTES){r->code_error=1;return;}r->code[r->used++]=(unsigned char)x;}
static void w86_bytes(W86_RUN *r,const unsigned char *p,size_t n){size_t i;for(i=0;i<n;i++)w86_b(r,p[i]);}
#define W86_BYTES(r,...) do{const unsigned char x_[]={__VA_ARGS__};w86_bytes((r),x_,sizeof x_);}while(0)
static void w86_begin(W86_RUN *r,W86_FN *fn){fn->entry=r->code+r->used;W86_BYTES(r,0x53);fn->fault_begin=r->code+r->used;W86_BYTES(r,0x49,0x89,0xc8);}
static void w86_end(W86_RUN *r,W86_FN *fn){fn->recover=r->code+r->used;W86_BYTES(r,0x5b,0xc3);fn->size=(size_t)(r->code+r->used-fn->entry);}
static void w86_cpuid_bytes(W86_RUN *r){W86_BYTES(r,0x31,0xc0,0x31,0xc9,0x0f,0xa2);}
static void w86_stamp_bytes(W86_RUN *r,unsigned kind){if(kind)W86_BYTES(r,0x0f,0x01,0xf9);else W86_BYTES(r,0x0f,0x31);}
static void w86_store_stamp(W86_RUN *r,unsigned kind,unsigned offset){
 /* MOV [R8+disp8],EAX/EDX/ECX. uint64 result is little-endian EDX:EAX. */
 W86_BYTES(r,0x41,0x89,0x40,offset,0x41,0x89,0x50,offset+4);
 if(kind)W86_BYTES(r,0x41,0x89,0x48,offset+8);
 else W86_BYTES(r,0x41,0xc7,0x40,offset+8,0,0,0,0);
}
static void w86_emit_code(W86_RUN *r){unsigned k,ordered;
 for(k=0;k<2;k++)for(ordered=0;ordered<2;ordered++){W86_FN *fn=ordered?&r->ordered[k]:&r->raw[k];w86_begin(r,fn);
  if(ordered){if(r->lfence){if(!k)W86_BYTES(r,0x0f,0xae,0xe8);}else w86_cpuid_bytes(r);}
  w86_stamp_bytes(r,k);
  if(ordered&&r->lfence)W86_BYTES(r,0x0f,0xae,0xe8);
  w86_store_stamp(r,k,0);
  if(ordered&&!r->lfence)w86_cpuid_bytes(r);
  w86_end(r,fn);
 }
 for(k=0;k<2;k++){W86_FN *fn=&r->pair[k];w86_begin(r,fn);w86_cpuid_bytes(r);w86_stamp_bytes(r,k);
  /* The only instructions between the raw reads retain their first results. */
  W86_BYTES(r,0x41,0x89,0xc1,0x41,0x89,0xd2);if(k)W86_BYTES(r,0x41,0x89,0xcb);
  w86_stamp_bytes(r,k);w86_store_stamp(r,k,16);
  W86_BYTES(r,0x45,0x89,0x08,0x45,0x89,0x50,4);if(k)W86_BYTES(r,0x45,0x89,0x58,8);else W86_BYTES(r,0x41,0xc7,0x40,8,0,0,0,0);
  w86_cpuid_bytes(r);w86_end(r,fn);
 }
 w86_begin(r,&r->cpuid);w86_cpuid_bytes(r);w86_end(r,&r->cpuid);
 w86_begin(r,&r->loop);W86_BYTES(r,0xb9,0xe8,0x03,0,0,0xff,0xc9,0x75,0xfc);w86_end(r,&r->loop);
}
static int w86_make_code(W86_RUN *r,DWORD *error){DWORD old;
 r->code=(unsigned char*)VirtualAlloc(NULL,W86_CODE_BYTES,MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE);if(!r->code){*error=GetLastError();return 0;}
 w86_emit_code(r);
 if(r->code_error){*error=ERROR_INSUFFICIENT_BUFFER;return 0;}
 if(!VirtualProtect(r->code,W86_CODE_BYTES,PAGE_EXECUTE_READ,&old)||!FlushInstructionCache(GetCurrentProcess(),r->code,r->used)){*error=GetLastError();return 0;}
 return 1;
}
static LONG CALLBACK w86_veh(EXCEPTION_POINTERS *ep){W86_RUN *r=w86_active;W86_FN *fn;EXCEPTION_RECORD *e;CONTEXT *c;
 if(!r||GetCurrentThreadId()!=r->owner)return EXCEPTION_CONTINUE_SEARCH;
 e=ep->ExceptionRecord;c=ep->ContextRecord;
 if(r->raising&&e->ExceptionCode==W86_EXCEPTION_CODE&&(e->ExceptionFlags&~(DWORD)EXCEPTION_SOFTWARE_ORIGINATE)==0&&e->NumberParameters==1&&e->ExceptionInformation[0]==(ULONG_PTR)(uintptr_t)r){r->deliveries++;return EXCEPTION_CONTINUE_EXECUTION;}
 fn=r->active_fn;if(!fn||(e->ExceptionFlags&EXCEPTION_NONCONTINUABLE)||c->Rip<(DWORD64)(uintptr_t)fn->fault_begin||c->Rip>=(DWORD64)(uintptr_t)fn->recover)return EXCEPTION_CONTINUE_SEARCH;
 r->fault_code=e->ExceptionCode;c->Rip=(DWORD64)(uintptr_t)fn->recover;return EXCEPTION_CONTINUE_EXECUTION;
}
static int w86_call(W86_RUN *r,W86_FN *code,W86_STAMP *output){typedef void (*FN)(W86_STAMP*);FN fn;void *entry=code->entry;memcpy(&fn,&entry,sizeof fn);r->fault_code=0;r->active_fn=code;fn(output);r->active_fn=NULL;return r->fault_code==0;}
static int w86_same_cpu(PROCESSOR_NUMBER p,WORD group,unsigned cpu){return p.Group==group&&p.Number==cpu;}
static int w86_workload(W86_RUN *r,unsigned work){
 if(work==1)return w86_call(r,&r->cpuid,NULL);
 if(work==2)return w86_call(r,&r->loop,NULL);
 if(work==3)return WaitForSingleObject(r->event,0)==WAIT_TIMEOUT;
 if(work==4){ULONG_PTR cookie=(ULONG_PTR)(uintptr_t)r;LONG before=r->deliveries;r->raising=1;RaiseException(W86_EXCEPTION_CODE,0,1,&cookie);r->raising=0;return r->deliveries==before+1;}
 return 1;
}
static int w86_sample(W86_RUN *r,unsigned kind,unsigned work,W86_STAMP pair[2]){
 int ok;if(work==5)return w86_call(r,&r->pair[kind],pair);
 if(!w86_call(r,&r->ordered[kind],&pair[0]))return 0;
 ok=w86_workload(r,work);if(r->fault_code)return 0;
 if(!w86_call(r,&r->ordered[kind],&pair[1]))return 0;
 return ok;
}
static int w86_distribution(FILE *f,W86_RUN *r,unsigned kind,unsigned work,WORD group,unsigned cpu){
 W86_DISTRIBUTION d;unsigned i;memset(&d,0,sizeof d);
 for(i=0;i<W86_WARMUP;i++){W86_STAMP pair[2];(void)w86_sample(r,kind,work,pair);if(r->fault_code)break;}
 if(r->fault_code)d.instruction_fault=r->fault_code;
 else for(i=0;i<W86_SAMPLES;i++){W86_STAMP pair[2];PROCESSOR_NUMBER p0,p1;int ok;GetCurrentProcessorNumberEx(&p0);ok=w86_sample(r,kind,work,pair);GetCurrentProcessorNumberEx(&p1);d.attempted++;
  if(r->fault_code){d.instruction_fault=r->fault_code;d.failed++;break;}
  if(!ok)d.failed++;else if(!w86_same_cpu(p0,group,cpu)||!w86_same_cpu(p1,group,cpu)||(kind&&pair[0].aux!=pair[1].aux))d.migrated++;else if(pair[1].tsc<pair[0].tsc)d.backwards++;else d.value[d.valid++]=pair[1].tsc-pair[0].tsc;
 }
 w86_emit_distribution(f,&d);return d.instruction_fault==0;
}
static int w86_monotonic(FILE *f,W86_RUN *r,unsigned kind,int ordered,WORD group,unsigned cpu){
 unsigned i,reads=0,backwards=0,equal=0,aux_changes=0;W86_STAMP first={0,0,0},previous={0,0,0};PROCESSOR_NUMBER p0,p1;W86_FN *fn=ordered?&r->ordered[kind]:&r->raw[kind];GetCurrentProcessorNumberEx(&p0);
 for(i=0;i<W86_MONO_READS;i++){W86_STAMP now;if(!w86_call(r,fn,&now))break;if(reads){backwards+=now.tsc<previous.tsc;equal+=now.tsc==previous.tsc;aux_changes+=kind&&now.aux!=previous.aux;}else first=now;previous=now;reads++;}
 GetCurrentProcessorNumberEx(&p1);fprintf(f,"{\"requested\":%u,\"reads\":%u,\"comparisons\":%u,\"backwards\":%u,\"equal\":%u,\"aux_changes\":%u,\"instruction_fault\":%lu,\"cpu_before\":{\"group\":%u,\"number\":%u},\"cpu_after\":{\"group\":%u,\"number\":%u},\"affinity_cpu_confirmed_at_endpoints\":%s,\"first_tsc\":%" PRIu64 ",\"last_tsc\":%" PRIu64 ",\"first_aux\":%u,\"last_aux\":%u}",W86_MONO_READS,reads,reads?reads-1:0,backwards,equal,aux_changes,(unsigned long)r->fault_code,p0.Group,p0.Number,p1.Group,p1.Number,w86_bool(w86_same_cpu(p0,group,cpu)&&w86_same_cpu(p1,group,cpu)),first.tsc,previous.tsc,first.aux,previous.aux);return r->fault_code==0;
}
static int w86_clock(FILE *f,W86_RUN *r,unsigned kind,WORD group,unsigned cpu){
 LARGE_INTEGER frequency;unsigned i;uint64_t previous_mid=0;LONGLONG previous_qpc=0;uint32_t previous_aux=0;int previous_valid=0,ok=1;
 if(!QueryPerformanceFrequency(&frequency)||frequency.QuadPart<=0){fputs("{\"status\":\"qpc_frequency_unavailable\"}",f);return 1;}
 fprintf(f,"{\"clock\":\"QueryPerformanceCounter\",\"frequency_hz\":%" PRId64 ",\"nominal_sleep_ms\":20,\"anchors\":[",(int64_t)frequency.QuadPart);
 for(i=0;i<=W86_CLOCK_INTERVALS;i++){W86_STAMP a={0,0,0},b={0,0,0};PROCESSOR_NUMBER p0,p1;LARGE_INTEGER qpc;int valid,got;uint64_t mid=0;DWORD error=0;qpc.QuadPart=0;if(i)Sleep(20);GetCurrentProcessorNumberEx(&p0);
  if(!w86_call(r,&r->ordered[kind],&a)){ok=0;break;}got=QueryPerformanceCounter(&qpc);if(!got)error=GetLastError();if(!w86_call(r,&r->ordered[kind],&b)){ok=0;break;}GetCurrentProcessorNumberEx(&p1);
  valid=got&&qpc.QuadPart>=0&&b.tsc>=a.tsc&&w86_same_cpu(p0,group,cpu)&&w86_same_cpu(p1,group,cpu)&&(!kind||a.aux==b.aux);if(valid)mid=a.tsc+(b.tsc-a.tsc)/2u;if(i)fputc(',',f);
  fprintf(f,"{\"index\":%u,\"valid\":%s,\"qpc_error\":%lu,\"qpc_ticks\":%" PRId64 ",\"tsc_before\":%" PRIu64 ",\"tsc_after\":%" PRIu64 ",\"aux_before\":%u,\"aux_after\":%u,\"cpu_before\":{\"group\":%u,\"number\":%u},\"cpu_after\":{\"group\":%u,\"number\":%u},\"tsc_ticks_per_second_from_previous\":",i,w86_bool(valid),(unsigned long)error,(int64_t)qpc.QuadPart,a.tsc,b.tsc,a.aux,b.aux,p0.Group,p0.Number,p1.Group,p1.Number);
  if(valid&&previous_valid&&qpc.QuadPart>previous_qpc&&mid>=previous_mid&&(!kind||a.aux==previous_aux))fprintf(f,"%.3f",((double)(mid-previous_mid)/(double)(qpc.QuadPart-previous_qpc))*(double)frequency.QuadPart);else fputs("null",f);fputc('}',f);previous_valid=valid;previous_mid=mid;previous_qpc=qpc.QuadPart;previous_aux=b.aux;
 }
 fprintf(f,"],\"instruction_fault\":%lu}",(unsigned long)r->fault_code);return ok;
}
static int windows_timing_measure(const char *path){
 static const char *worknames[6]={"adjacent_ordered","cpuid_leaf0","empty_1000_iteration_loop","win32_zero_timeout_event_wait","continuable_exception_delivery_and_return","adjacent_raw"};
 W86_RUN r;GROUP_AFFINITY original,selected,verified;FILE *f;DWORD setup_error=0,affinity_error=0,restore_error=0,handler_remove_error=0,event_error=0,free_error=0;WORD group_count=GetActiveProcessorGroupCount();unsigned c0[4]={0},c1[4]={0},ce[4]={0},ce1[4]={0},ce7[4]={0},ce21[4]={0},c15[4]={0},k,work,cpu=0;char vendor[13];int pinned=0,changed=0,cpok,rc=0;const char *environment=getenv("T86_ENVIRONMENT");
 memset(&r,0,sizeof r);memset(&original,0,sizeof original);memset(&selected,0,sizeof selected);memset(&verified,0,sizeof verified);r.owner=GetCurrentThreadId();
 f=fopen(path,"w");if(!f){fprintf(stderr,"timing: cannot open output file %s\n",path);return 1;}
 cpok=win_cp(0,0,c0)&&win_cp(0x80000000u,0,ce);if(cpok&&c0[0]>=1)cpok=win_cp(1,0,c1);if(cpok&&ce[0]>=0x80000001u)cpok=win_cp(0x80000001u,0,ce1);if(cpok&&ce[0]>=0x80000007u)cpok=win_cp(0x80000007u,0,ce7);if(cpok&&ce[0]>=0x80000021u)cpok=win_cp(0x80000021u,0,ce21);if(cpok&&c0[0]>=0x15)cpok=win_cp(0x15,0,c15);
 memcpy(vendor,&c0[1],4);memcpy(vendor+4,&c0[3],4);memcpy(vendor+8,&c0[2],4);vendor[12]=0;r.lfence=!strcmp(vendor,"GenuineIntel")||(!strcmp(vendor,"AuthenticAMD")&&(ce21[0]&(1u<<2)));
 fputs("{\n\"schema\":\"0086-windows-timing-v1\",\n\"platform\":\"Windows_x64\",\n\"run_status\":\"EXECUTED_ON_THIS_HOST\",\n\"canonical_cells\":[13224,13225,13226,13227,13228,13229,13230],\n\"execution_environment\":",f);w86_json_string(f,environment?environment:"unspecified_by_operator");fputs(",\n\"environment_label_source\":\"T86_ENVIRONMENT; not inferred from CPUID\",\n\"cpu_vendor\":",f);w86_json_string(f,vendor);
 fprintf(f,",\n\"cpuid_available\":%s,\n\"cpuid_hypervisor_bit\":%s,\n\"cpuid_tsc\":%s,\n\"cpuid_rdtscp\":%s,\n\"cpuid_invariant_tsc\":%s,\n\"cpuid_15\":{\"denominator\":%u,\"numerator\":%u,\"crystal_hz\":%u},\n",w86_bool(cpok),w86_bool(c1[2]&(1u<<31)),w86_bool(c1[3]&(1u<<4)),w86_bool(ce1[3]&(1u<<27)),w86_bool(ce7[3]&(1u<<8)),c15[0],c15[1],c15[2]);
 fprintf(f,"\"ordering\":\"%s\",\n",r.lfence?"RDTSC: LFENCE;RDTSC;LFENCE. RDTSCP: RDTSCP;LFENCE":"CPUID(0);timestamp-read;store-result;CPUID(0) for both ordered readers; CPUID fences included in intervals");
 fputs("\"interpretation\":\"TSC ticks, not core cycles. Calls, result stores, control flow and timestamp overhead are included, never subtracted. Raw pairs have only register-retention moves between reads. Scheduling, interrupts and virtualization remain. Timing is excluded from the CELL checksum.\",\n\"os_differences\":{\"syscall_cell_13228\":\"WaitForSingleObject(private unsignaled event,0), expected WAIT_TIMEOUT. Documented Win32 kernel-object wait boundary; implementation-specific kernel-transition count is not asserted. Not the Linux getpid workload; no native syscall numbers.\",\"signal_cell_13229\":\"RaiseException with a private continuable application exception, scoped VEH handles only this own-thread cookie, return through RaiseException. Windows has no POSIX signal/rt_sigreturn here; not the Linux signal workload.\",\"clock_cell_13230\":\"QueryPerformanceCounter/QueryPerformanceFrequency, not clock_gettime. QPC may itself use TSC; correlation is not an independent clock validation.\"},\n",f);
 if(!GetThreadGroupAffinity(GetCurrentThread(),&original))affinity_error=GetLastError();
 else if(!original.Mask)affinity_error=ERROR_INVALID_PARAMETER;
 else{selected=original;selected.Mask=original.Mask&(~original.Mask+1);while(((KAFFINITY)1<<cpu)!=selected.Mask&&cpu<sizeof(KAFFINITY)*8u-1u)cpu++;
  if(!SetThreadGroupAffinity(GetCurrentThread(),&selected,NULL))affinity_error=GetLastError();else{changed=1;if(!GetThreadGroupAffinity(GetCurrentThread(),&verified))affinity_error=GetLastError();else if(verified.Group!=selected.Group||verified.Mask!=selected.Mask)affinity_error=ERROR_INVALID_PARAMETER;else pinned=1;}
 }
 fprintf(f,"\"affinity\":{\"scope\":\"new owned timing thread only; narrow its current group mask to one processor; main thread affinity untouched\",\"active_processor_groups\":%u,\"original_group\":%u,\"original_mask\":\"0x%016" PRIx64 "\",\"selected_group\":%u,\"selected_cpu\":%u,\"pinned_and_verified\":%s,\"error\":%lu},\n",group_count,original.Group,(uint64_t)original.Mask,selected.Group,cpu,w86_bool(pinned),(unsigned long)affinity_error);
 if(!cpok||!pinned){fprintf(f,"\"status\":\"%s\",\n\"timers\":[]",!cpok?"not_measured_cpuid_setup_failed":"not_measured_affinity_unavailable_no_fallback_or_bypass");rc=2;goto cleanup;}
 if(!w86_make_code(&r,&setup_error)){fprintf(f,"\"status\":\"not_measured_code_setup_failed\",\"error\":%lu,\"timers\":[]",(unsigned long)setup_error);rc=2;goto cleanup;}
 w86_active=&r;r.handler=AddVectoredExceptionHandler(1,w86_veh);if(!r.handler){setup_error=GetLastError();fprintf(f,"\"status\":\"not_measured_veh_setup_failed\",\"error\":%lu,\"timers\":[]",(unsigned long)setup_error);rc=2;goto cleanup;}
 r.event=CreateEventW(NULL,TRUE,FALSE,NULL);if(!r.event)event_error=GetLastError();
 fputs("\"status\":\"measurement_attempted\",\n\"quantiles\":\"Median: mean of middle two for even n; p99: nearest rank ceil(0.99*n). All valid observations retained.\",\n\"timers\":[",f);
 for(k=0;k<2;k++){W86_STAMP probe;int advertised=k?!!(ce1[3]&(1u<<27)):!!(c1[3]&(1u<<4)),healthy=1;if(k)fputc(',',f);fprintf(f,"{\"instruction\":\"%s\",\"cpuid_advertised\":%s,",k?"RDTSCP":"RDTSC",w86_bool(advertised));
  if(!advertised){fputs("\"status\":\"skipped_cpuid_absent\"}",f);continue;}
  if(!w86_call(&r,&r.ordered[k],&probe)){fprintf(f,"\"status\":\"not_executable\",\"exception_code\":%lu}",(unsigned long)r.fault_code);continue;}
  fputs("\"status\":\"measurement_attempted\",\"monotonicity_ordered\":",f);healthy=w86_monotonic(f,&r,k,1,selected.Group,cpu);fputs(",\"monotonicity_raw\":",f);if(healthy)healthy=w86_monotonic(f,&r,k,0,selected.Group,cpu);else fputs("{\"status\":\"not_measured_after_instruction_fault\"}",f);
  fputs(",\"distributions\":{",f);for(work=0;work<6;work++){if(work)fputc(',',f);fprintf(f,"\"%s\":",worknames[work]);if(!healthy)fputs("{\"status\":\"not_measured_after_instruction_fault\"}",f);else if(work==3&&!r.event)fprintf(f,"{\"status\":\"event_setup_failed\",\"error\":%lu}",(unsigned long)event_error);else healthy=w86_distribution(f,&r,k,work,selected.Group,cpu);}
  fputs("},\"qpc_relation\":",f);if(healthy)healthy=w86_clock(f,&r,k,selected.Group,cpu);else fputs("{\"status\":\"not_measured_after_instruction_fault\"}",f);fprintf(f,",\"instruction_fault_stopped_measurement\":%s}",w86_bool(!healthy));if(!healthy)rc=2;
 }
 fputs("]",f);
cleanup:
 r.raising=0;r.active_fn=NULL;
 if(r.handler&&!RemoveVectoredExceptionHandler(r.handler))handler_remove_error=GetLastError();
 w86_active=NULL;
 if(r.event&&!CloseHandle(r.event))event_error=GetLastError();
 if(r.code&&!VirtualFree(r.code,0,MEM_RELEASE))free_error=GetLastError();
 if(changed){if(!SetThreadGroupAffinity(GetCurrentThread(),&original,NULL))restore_error=GetLastError();else if(!GetThreadGroupAffinity(GetCurrentThread(),&verified))restore_error=GetLastError();else if(verified.Group!=original.Group||verified.Mask!=original.Mask)restore_error=ERROR_INVALID_PARAMETER;}
 fprintf(f,",\n\"cleanup\":{\"worker_group_mask_restore_error\":%lu,\"veh_remove_error\":%lu,\"event_error\":%lu,\"code_free_error\":%lu,\"affinity_restore_scope\":\"Saved worker group/mask only; no claim of restoring an original all-groups default. Worker exits after measurement; main thread was never changed.\"},\n\"exception_deliveries_including_warmup\":%ld\n}\n",(unsigned long)restore_error,(unsigned long)handler_remove_error,(unsigned long)event_error,(unsigned long)free_error,(long)r.deliveries);
 if(restore_error||handler_remove_error||event_error||free_error)rc=1;if(ferror(f))rc=1;if(fclose(f))rc=1;return rc;
}
/* A dedicated worker avoids changing the main thread's Windows 11 default
 * cross-group affinity. GetThreadGroupAffinity captures only one group mask.
 * On failed/expired join the process exits rather than leaving a live thread
 * referencing this stack, removing its handler, or claiming completed JSON. */
typedef struct {const char *path;int result;} W86_JOB;
static DWORD WINAPI w86_thread(void *opaque){W86_JOB *job=(W86_JOB*)opaque;job->result=windows_timing_measure(job->path);return (DWORD)job->result;}
static int windows_timing_run(const char *path){W86_JOB job;HANDLE thread;DWORD wait,error;job.path=path;job.result=2;
 thread=CreateThread(NULL,0,w86_thread,&job,0,NULL);if(!thread){fprintf(stderr,"timing: own thread creation failed: %lu\n",(unsigned long)GetLastError());return 2;}
 wait=WaitForSingleObject(thread,120000);if(wait!=WAIT_OBJECT_0){error=wait==WAIT_FAILED?GetLastError():wait;fprintf(stderr,"timing: own worker join failed or timed out: %lu; stopping this probe process; JSON may be incomplete\n",(unsigned long)error);ExitProcess(6);return 6;}
 if(!CloseHandle(thread)){fprintf(stderr,"timing: own thread handle close failed: %lu\n",(unsigned long)GetLastError());return 1;}return job.result;
}
/* WINDOWS_B7_TIMING_END */

#endif /* !LIST_ONLY */

static void list_cells(void){unsigned i;uint64_t h=UINT64_C(14695981039346656037);char line[256];for(i=0;i<cell_count;i++){size_t j;int n=snprintf(line,sizeof line,"CELL %u %s\n",i,cells[i].name);fputs(line,stdout);for(j=0;j<(size_t)n;j++){h^=(unsigned char)line[j];h*=UINT64_C(1099511628211);}}printf("TOTAL cells=%u fnv1a64=%016llx\n",cell_count,(unsigned long long)h);}
#if !defined(LIST_ONLY)
static int number(const char*s,unsigned*v){char*e;unsigned long n;if(!s||!*s||*s=='-')return 0;n=strtoul(s,&e,10);if(*e||n>=cell_count)return 0;*v=(unsigned)n;return 1;}
#endif
int main(int argc,char**argv){unsigned first=0,last,i;int worker=0;build_cells();last=cell_count-1;if(argc==2&&!strcmp(argv[1],"list")){list_cells();return 0;}
#if defined(LIST_ONLY)
 (void)first;(void)last;(void)i;(void)worker;fputs("LIST_ONLY build supports only list\n",stderr);return 2;
#else
 if(argc==3&&!strcmp(argv[1],"timing")){int result;if(!install_handler()){fprintf(stderr,"VEH install failed: %lu\n",(unsigned long)GetLastError());return 3;}result=windows_timing_run(argv[2]);remove_handler();return result;}
 if(argc==3&&!strcmp(argv[1],"--worker")&&number(argv[2],&first)){last=first;worker=1;}
 else if(argc==2&&!strcmp(argv[1],"all")){}
 else if(argc==3&&!strcmp(argv[1],"cell")&&number(argv[2],&first))last=first;
 else if(argc==4&&!strcmp(argv[1],"range")&&number(argv[2],&first)&&number(argv[3],&last)&&first<=last){}
 else{fputs("usage: windows_probe.exe all | cell N | range A B | list | timing FILE.json\n",stderr);return 2;}
 if(worker)SetErrorMode(SEM_FAILCRITICALERRORS|SEM_NOGPFAULTERRORBOX);
 if(!install_handler()){fprintf(stderr,"VEH install failed: %lu\n",(unsigned long)GetLastError());return 3;}
 if(!worker)printf("META schema=0086.windows.v1 platform=Windows_x64 run_status=EXECUTED_ON_THIS_HOST vector_error=NOT_EXPOSED_BY_WIN32 address_raw_and_relative=1\n");
 init_machine();if(!worker)printf("META xcr0=0x%016llx\n",(unsigned long long)win_xcr0);for(i=first;i<=last;i++){unsigned k=cells[i].kind;if(!worker&&(k==K_TRAP||k==K_PREFIX||k==K_MEMORY||k==K_STEP))isolated_cell(i);else run_cell(i);if(isolation_abort)break;}remove_handler();if(!worker)printf("TOTAL cells=%u fnv1a64=%016llx\n",lines,(unsigned long long)checksum);return isolation_abort?5:0;
#endif
}
