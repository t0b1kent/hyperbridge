from pathlib import Path
out=Path(__file__).resolve().with_name('asm_fragment.h')
seed=[0x1100000000000001,0x2200000000000002,0x3300000000000003,0x4400000000000004,0,0,0x7700000000000007,0x8800000000000008]+[0x9000000000000000+i for i in range(8,16)]
lines=['''/* Own-code Windows x64 probe assembly. Include once in a C11 translation unit.
 * GPR order follows Windows CONTEXT: rax rcx rdx rbx rsp rbp rsi rdi r8..r15.
 * RBP is a runtime frame anchor, not a literal seed. RSP is also runtime-valued.
 * Each sled byte is one complete PUSHFQ; no GPR or arithmetic flag is modified.
 * The fixed allocation includes 128 bytes below instruction RSP. Patterning and
 * sled stores stay inside that allocation, below all saved/unwind state.
 * The final POPFQ scratch occupies the upper eight bytes of the lower window.
 * Its lower 120 bytes were primed with A5; after RSP rises this region is
 * volatile under the Windows ABI, including during exception delivery.
 * No executable code from a DLL is read, patched, or decoded.
 */
#ifndef EXCEPTION_OBSERVER_ASM_FRAGMENT_H
#define EXCEPTION_OBSERVER_ASM_FRAGMENT_H
#include <stdint.h>
#if !defined(__clang__) || !defined(_WIN64) || !defined(__x86_64__)
#error This probe requires llvm-mingw clang for Windows x86-64.
#endif
volatile uint64_t requested_flags;
volatile uint64_t probe_pre_rsp, probe_pre_rbp;
volatile uint64_t probe_post_gpr[16], probe_post_rflags, probe_last_rflags;
volatile uint64_t requested_rax;
extern const char own_debug_a[];
extern const wchar_t own_debug_w[];
extern volatile long own_remote_present;
/* UINT64_MAX means no valid measured entry. Range 0..8 denotes sled offsets. */
volatile uint64_t probe_sled_entry = UINT64_MAX;
volatile uint64_t probe_completed, probe_escape_taken, probe_capture_path;
volatile uint64_t probe_raise_parameter = UINT64_C(0x123456789abcdef0);
volatile uint64_t probe_seed_gpr[16];
__attribute__((aligned(16), used)) const uint64_t probe_base_seed_gpr[16] = {''']
lines += ['    '+', '.join(f'UINT64_C(0x{x:016x})' for x in seed[i:i+4])+',' for i in range(0,16,4)]
lines += ['};','__attribute__((aligned(16), used)) const uint64_t probe_stack_pattern[2] = {','    UINT64_C(0xa5a5a5a5a5a5a5a5), UINT64_C(0xa5a5a5a5a5a5a5a5)','};','__attribute__((aligned(16), used)) const uint64_t probe_xmm_seed[16][2] = {']
lines += [f'    {{ UINT64_C(0x{0x5a00000000000000+i:016x}), UINT64_C(0x{0xa500000000000000+i:016x}) }},' for i in range(16)]
lines += ['};','']
cells=[('int2d', 'movq requested_rax(%rip),%rax\nmovq %rax,probe_seed_gpr+0(%rip)', '.byte 0xcd,0x2d', False),
('int3', '', '.byte 0xcc', False),
('debugbreak', '', 'call *__imp_DebugBreak(%rip)', False),
('output_a', 'leaq own_debug_a(%rip),%rax\nmovq %rax,probe_seed_gpr+8(%rip)', 'call *__imp_OutputDebugStringA(%rip)', False),
('output_w', 'leaq own_debug_w(%rip),%rax\nmovq %rax,probe_seed_gpr+8(%rip)', 'call *__imp_OutputDebugStringW(%rip)', False),
('is_debugger_present', '', 'call *__imp_IsDebuggerPresent(%rip)', False),
('check_remote_debugger_present', 'movq $-1,probe_seed_gpr+8(%rip)\nleaq own_remote_present(%rip),%rax\nmovq %rax,probe_seed_gpr+16(%rip)', 'call *__imp_CheckRemoteDebuggerPresent(%rip)', False),
('alternate', '', '', False)]
for name,*_ in cells:
    lines += [f'extern void probe_{name}(void);',f'extern const unsigned char probe_{name}_site[], probe_{name}_sled_start[],',f'    probe_{name}_sled_end[], probe_{name}_escape[], probe_{name}_end[];']
lines += ['','/* The assembler emits one RUNTIME_FUNCTION / UNWIND_INFO per function. */','__asm__(']
asm=[]
def emit(s): asm.extend(s.splitlines())
def label(name): emit(f'.globl {name}\n{name}:')
regs=['rax','rcx','rdx','rbx','rsp','rbp','rsi','rdi']+[f'r{i}' for i in range(8,16)]
for name,config,target,tf in cells:
    n='probe_'+name
    emit(f'\n# {n}: independent fixed probe function\n.text\n.p2align 4\n.globl {n}\n.seh_proc {n}\n{n}:')
    for r in ['rbp','rbx','rsi','rdi','r12','r13','r14','r15']:
        emit(f'pushq %{r}\n.seh_pushreg %{r}')
    emit('subq $0x228,%rsp\n.seh_stackalloc 0x228')
    for i in range(6,16):
        off=0x180+16*(i-6)
        emit(f'movdqu %xmm{i},0x{off:x}(%rsp)\n.seh_savexmm %xmm{i},0x{off:x}')
    emit('leaq 0x80(%rsp),%rbp\n.seh_setframe %rbp,0x80\n.seh_endprologue')
    if name != 'alternate':
        emit('# Move within the allocated frame before any scratch push.\nmovq %rbp,%rsp\n# Flags storage is above instruction RSP and below nonvolatile saves.\npushfq\npopq %rax\nmovq %rax,0xf8(%rbp)')
        emit('# Lower RSP before priming the already allocated lower 128 bytes.\nleaq -0x80(%rbp),%rsp\nmovdqu probe_stack_pattern(%rip),%xmm0')
        for off in range(0,0x80,16): emit(f'movdqu %xmm0,{off-0x80}(%rbp)')
        emit('# Clear output validity and leave unmistakable unexecuted snapshots.\nmovq $0,probe_completed(%rip)\nmovq $0,probe_escape_taken(%rip)\nmovq $0,probe_capture_path(%rip)\nmovq $-1,probe_sled_entry(%rip)\nmovq $-1,probe_post_rflags(%rip)')
        for off in range(0,128,16):emit(f'movdqu %xmm0,probe_post_gpr+{off}(%rip)')
        emit('# Reset per-call expectations, including API argument overrides below.')
        for off in range(0,128,16):emit(f'movdqu probe_base_seed_gpr+{off}(%rip),%xmm0\nmovdqu %xmm0,probe_seed_gpr+{off}(%rip)')
        emit('movq %rbp,%rsp\nmovq %rsp,probe_pre_rsp(%rip)\nmovq %rbp,probe_pre_rbp(%rip)\nmovq %rsp,probe_seed_gpr+32(%rip)\nmovq %rbp,probe_seed_gpr+40(%rip)')
        if config:emit(config)
        emit('# Arithmetic mask CF|PF|AF|ZF|SF|OF=0x8d5; retain other caller bits.\nmovq 0xf8(%rbp),%rax\nandq $-2262,%rax\nmovq requested_flags(%rip),%rdx\nandq $0x8d5,%rdx\norq %rdx,%rax')
        if tf:emit('orq $0x100,%rax # Enable TF only immediately before the NOP below.')
        emit('movq %rax,0xf0(%rbp)')
        for i in range(16): emit(f'movdqu probe_xmm_seed+{i*16}(%rip),%xmm{i}')
        for i,r in enumerate(regs):
            if r not in ['rsp','rbp']:emit(f'movq probe_seed_gpr+{i*8}(%rip),%{r}')
        emit('# POPFQ is the last instruction before the target; no seed disturbs flags.\npushq 0xf0(%rbp)\npopfq')
    label(n+'_site');emit(target)
    label(n+'_sled_start');emit('.byte 0x9c,0x9c,0x9c,0x9c,0x9c,0x9c,0x9c,0x9c,0x9c')
    label(n+'_sled_end')
    emit('# Capture before touching any GPR, RSP, or arithmetic flags.')
    for i,r in enumerate(regs):emit(f'movq %{r},probe_post_gpr+{i*8}(%rip)')
    emit(f'movq ${2 if name == "alternate" else 1},probe_capture_path(%rip) # Observed path, independent of requested RIP edit.')
    emit('# FIRST image is at pre_rsp-8, not top of stack: TF handler can change TF after first PUSHFQ.\nmovq probe_pre_rsp(%rip),%rax\nmovq -8(%rax),%rax\nmovq %rax,probe_post_rflags(%rip)\nmovq (%rsp),%rax\nmovq %rax,probe_last_rflags(%rip)')
    emit(f'movq probe_pre_rsp(%rip),%rax\nsubq %rsp,%rax\ncmpq $8,%rax\njb {n}_bad_delta\ncmpq $72,%rax\nja {n}_bad_delta\ntestq $7,%rax\njnz {n}_bad_delta\nshrq $3,%rax\nmovq $9,%rcx\nsubq %rax,%rcx\nmovq %rcx,probe_sled_entry(%rip)\n{n}_bad_delta:\nmovq $1,probe_completed(%rip)\njmp {n}_cleanup')
    label(n+'_escape');emit(f'movq $1,probe_escape_taken(%rip)\nmovq $1,probe_completed(%rip)\njmp {n}_cleanup')
    emit(n+'_cleanup:\n# Restore caller state using the stable frame anchor, even after sled pushes.\npushq 0xf8(%rbp)\npopfq')
    for i in range(6,16):
        off=0x100+16*(i-6)
        emit(f'movdqu 0x{off:x}(%rbp),%xmm{i}')
    emit('# Canonical frame-pointer epilogue: LEA then pops then RET.\nleaq 0x1a8(%rbp),%rsp')
    for r in ['r15','r14','r13','r12','rdi','rsi','rbx','rbp']:emit(f'popq %{r}')
    emit('retq\n.seh_endproc');label(n+'_end')
import json
lines += ['    '+json.dumps(s+'\n') for s in asm]
lines += [');','#endif','']
out.write_text('\n'.join(lines))
print(out, 'bytes=',out.stat().st_size)
