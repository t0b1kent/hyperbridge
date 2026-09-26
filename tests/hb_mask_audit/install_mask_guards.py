#!/usr/bin/env python3
"""Anchored patch builder for fc6a28e. Does not write source without --apply.
Reads the caller's actual checkout, refuses missing/nonunique anchors, creates a
real unified diff with that file's line numbers, and keeps a preimage backup.
No network, no git commit, no push, no replacing an entire code generator.
"""
from pathlib import Path
import argparse, difflib, hashlib, json, os, subprocess
BASE='fc6a28e8e96155742d91834aa926e1b1789279db'
HELPER='''/* EVEX.aaa == 0 is unmasked, independently of the contents of k0.
 * Call this only for vector IR; target also contains branch addresses elsewhere.
 * Upper-register zeroing is not a substitute for element writemasking. */
static bool jit_evex_write_masked(const hb_ir_instr_t* instr) {
    const uint32_t t = instr ? (uint32_t)instr->target : 0u;
    return (t & HB_EVEX_TARGET_PRESENT) != 0 &&
           ((t >> HB_EVEX_TARGET_MASK_SHIFT) & 7u) != 0;
}

'''
MOV='static bool emit_native_xmm_mov(hb_codegen_buffer_t* buf, const hb_ir_instr_t* instr) {\n'
PAIR='''    if (load->op != HB_IR_LOAD || store->op != HB_IR_STORE) return false;
    if (!is_xmm_reg_operand(&load->dst) || !is_xmm_reg_operand(&store->src2) ||
'''
READ='''                r = hb_memory_read(ctx->memory, addr, xmm, bytes);
                if (r != HB_OK) return r;
                trace_mem_watch_bytes(ctx, "read", addr, xmm, bytes, NULL);
                return write_vec_reg_bytes_evex_masked(ctx, instr, xmm, bytes < 16 ? 16 : bytes, lane);
'''
READ_NEW='''                if (evex_target_present(instr) && evex_target_mask(instr) != 0) {
                    const uint64_t k = ctx->k[evex_target_mask(instr) & 7u];
                    /* Mask the memory footprint BEFORE reading, not just writeback.
                     * No read, translation or permission check for inactive lanes.
                     * Retire the vector only after every enabled lane succeeded. */
                    for (size_t off = 0; off < bytes; off += lane) {
                        if (!((k >> (off / lane)) & 1u)) continue;
                        const size_t n = bytes - off < lane ? bytes - off : lane;
                        r = hb_memory_read(ctx->memory, addr + off, xmm + off, n);
                        if (r != HB_OK) return r;
                        trace_mem_watch_bytes(ctx, "read", addr + off, xmm + off, n, NULL);
                    }
                } else {
                    r = hb_memory_read(ctx->memory, addr, xmm, bytes);
                    if (r != HB_OK) return r;
                    trace_mem_watch_bytes(ctx, "read", addr, xmm, bytes, NULL);
                }
                return write_vec_reg_bytes_evex_masked(ctx, instr, xmm, bytes < 16 ? 16 : bytes, lane);
'''
def one(s,old,new,label):
    n=s.count(old)
    if n!=1:raise ValueError(f'{label}: expected one anchor, found {n}; no source was modified')
    return s.replace(old,new,1)
def codegen(s):
    if 'static bool jit_evex_write_masked(' in s:raise ValueError('guards already installed')
    s=one(s,MOV,HELPER+MOV+'    if (!instr || jit_evex_write_masked(instr)) return false;\n','MOV')
    s=one(s,PAIR,PAIR.splitlines(keepends=True)[0]+'''    /* A masked LOAD or STORE must not enter the unconditional 128-bit fusion. */
    if (jit_evex_write_masked(load) || jit_evex_write_masked(store)) return false;
'''+PAIR.splitlines(keepends=True)[1],'pair')
    old_loop = """        const hb_ir_instr_t* instr = &block->instrs[i];
        if (instr->op != HB_IR_STORE) return false;
        if (instr->src1.type != HB_OP_MEM || instr->src1.size != HB_SIZE_128) return false;
"""
    new_loop = old_loop.replace("        if (instr->op != HB_IR_STORE) return false;\n",
        "        if (instr->op != HB_IR_STORE) return false;\n"
        "        /* The 128-byte pattern shortcut has no per-lane writemask. */\n"
        "        if (jit_evex_write_masked(instr)) return false;\n")
    s=one(s,old_loop,new_loop,'vector store loop matcher')
    for op,side in [('LOAD',0),('STORE',1)]:
        old=f'''        case HB_IR_{op}: {{
            if (instr->src1.type != HB_OP_MEM) return HB_ERR_INTERNAL;
            perepis_shirin_vzvesti();
'''
        new=old+f'''            if (jit_evex_write_masked(instr)) {{
                perepis_uchest(buf, {side}, instr->src1.size, SH_POM_NE_REG);
                return emit_interp_ir_helper(buf, instr);
            }}
'''
        s=one(s,old,new,op)
    return s
def interpreter(s):return one(s,READ,READ_NEW,'vector LOAD read footprint')
def main():
    p=argparse.ArgumentParser();p.add_argument('--repo',type=Path,default=Path.cwd());p.add_argument('--apply',action='store_true');p.add_argument('--include-load-fault-fix',action='store_true');p.add_argument('--only-load-fault-fix',action='store_true');p.add_argument('--allow-other-head',action='store_true');p.add_argument('--output',type=Path,default=Path('M01-local.patch'));a=p.parse_args()
    try:head=subprocess.check_output(['git','-C',str(a.repo),'rev-parse','HEAD'],text=True).strip()
    except (OSError,subprocess.CalledProcessError):raise SystemExit('not a readable git checkout')
    if head!=BASE and not a.allow_other_head:raise SystemExit(f'HEAD={head}, expected {BASE}; no changes. Review parallel changes before --allow-other-head.')
    changes=[]
    funcs=[] if a.only_load_fault_fix else [('src/hb_arm64_codegen.c',codegen)]
    if a.include_load_fault_fix or a.only_load_fault_fix:funcs.append(('src/hb_interpreter.c',interpreter))
    for rel,fun in funcs:
        path=a.repo/rel;old=path.read_text();new=fun(old);backup=path.with_suffix(path.suffix+'.before-M01')
        if a.apply and backup.exists():raise SystemExit(f'backup already exists: {backup}; refusing to overwrite')
        changes.append((path,rel,old,new,backup))
    diff=''.join(''.join(difflib.unified_diff(old.splitlines(True),new.splitlines(True),fromfile='a/'+rel,tofile='b/'+rel)) for _,rel,old,new,_ in changes)
    a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text(diff)
    if a.apply:
        # All transformations are validated before touching either source file.
        for path,rel,old,new,backup in changes:
            if path.read_text()!=old:raise SystemExit('source changed while preparing patch; refusing '+str(path))
            backup.write_text(old);temp=path.with_suffix(path.suffix+'.M01-tmp');temp.write_text(new);os.chmod(temp,path.stat().st_mode);os.replace(temp,path)
    print(json.dumps(dict(head=head,patch=str(a.output),applied=a.apply,files=[dict(path=rel,before_sha256=hashlib.sha256(old.encode()).hexdigest(),after_sha256=hashlib.sha256(new.encode()).hexdigest()) for _,rel,old,new,_ in changes]),indent=2))
if __name__=='__main__':main()
