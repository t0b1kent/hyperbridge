# SPDX-License-Identifier: MIT
# Copyright (c) 2026 HyperBridge contributors
"""Adapt only ABI/exception capture and object directives; preserve tested instructions."""
from pathlib import Path
import re


def once(text, old, new):
    if text.count(old) != 1:
        raise ValueError('Windows adapter anchor drift')
    return text.replace(old, new)


def adapt(stage):
    stage = Path(stage)
    p = stage / 'core.c'
    code = p.read_text()
    code = once(code, '#include <ucontext.h>', '#include <windows.h>\n#define sigjmp_buf int\n#define sigsetjmp(buffer, save) 0')
    lines = code.splitlines()
    handlers = [i for i, line in enumerate(lines) if line.startswith('static void handler(')]
    if len(handlers) != 1:
        raise ValueError('expected exactly one POSIX fault handler')
    lines[handlers[0]] = '''extern void oracle_fault_return(void);
static LONG CALLBACK handler(EXCEPTION_POINTERS *event) {
  DWORD code = event->ExceptionRecord->ExceptionCode;
  if (!active || (code != EXCEPTION_INT_DIVIDE_BY_ZERO && code != EXCEPTION_INT_OVERFLOW))
    return EXCEPTION_CONTINUE_SEARCH;
  CONTEXT *u = event->ContextRecord;
  Ctx *c = active;
  c->r1=u->Rax; c->r2=u->Rdx; c->r3=u->Rbx; c->r4=u->Rcx;
  c->fa=u->EFlags & 65535; c->trap=1;
  // Return through the assembly wrapper's saved nonvolatile registers. No SEH
  // unwind or longjmp crosses assembly without Windows unwind metadata.
  u->Rip=(DWORD64)(uintptr_t)&oracle_fault_return;
  return EXCEPTION_CONTINUE_EXECUTION;
}'''
    code = '\n'.join(lines) + '\n'
    posix = 'struct sigaction sa={0};sa.sa_sigaction=handler;sa.sa_flags=SA_SIGINFO;sigemptyset(&sa.sa_mask);sigaction(SIGFPE,&sa,0);'
    code = once(code, posix, 'if(!AddVectoredExceptionHandler(1,handler))return 2;')
    p.write_text(code)
    p = stage / 'build/core.S'
    lines = p.read_text().splitlines()
    out, entries, exits = [], 0, 0
    for line in lines:
        if line.startswith(('.type ', '.size ', '.section .note.GNU-stack')):
            continue
        if re.fullmatch(r'core_\d+:', line):
            out.extend([line, 'push %rdi', 'push %rsi', 'mov %rcx,%rdi'])
            entries += 1
        elif line == 'ret':
            out.extend(['pop %rsi', 'pop %rdi', 'ret'])
            exits += 1
        else:
            out.append(line)
    if not entries or entries != exits:
        raise ValueError('unbalanced Windows ABI wrapper adaptation')
    out.extend(['.globl oracle_fault_return', 'oracle_fault_return:',
                'pop %rbx', 'pop %rsi', 'pop %rdi', 'ret'])
    p.write_text('\n'.join(out) + '\n')
    return {'adapted_wrappers': entries, 'tested_instruction_changes': 0,
            'exception_capture': 'VEH saves actual CONTEXT GPR/EFLAGS then returns through wrapper epilogue'}
