#!/usr/bin/env python3
"""Local patch/guard unit tests. Not an execution of the complete HB code generator.
Compile the exact new predicate and exercise all aaa/z/present combinations.
Verify anchored transforms are fail-closed on missing/duplicated/already-patched
input and that removing any protected exit is detected by a source invariant.
"""
from pathlib import Path
import tempfile,subprocess,json,argparse
import install_mask_guards as I

def invariants(s):
    required=[I.HELPER,I.MOV+'    if (!instr || jit_evex_write_masked(instr)) return false;',
              'if (jit_evex_write_masked(load) || jit_evex_write_masked(store)) return false;']
    for op,side in [('LOAD',0),('STORE',1)]:
        required.append(f'''        case HB_IR_{op}: {{
            if (instr->src1.type != HB_OP_MEM) return HB_ERR_INTERNAL;
            perepis_shirin_vzvesti();
            if (jit_evex_write_masked(instr)) {{
                perepis_uchest(buf, {side}, instr->src1.size, SH_POM_NE_REG);
                return emit_interp_ir_helper(buf, instr);
            }}''')
    required.append('        if (jit_evex_write_masked(instr)) return false;')
    return all(x in s for x in required)
def main():
    p=argparse.ArgumentParser();p.add_argument('--out',type=Path,required=True);a=p.parse_args()
    before=I.MOV+'\n'+I.PAIR+'\n'
    for op in ('LOAD','STORE'):before+=f'''        case HB_IR_{op}: {{
            if (instr->src1.type != HB_OP_MEM) return HB_ERR_INTERNAL;
            perepis_shirin_vzvesti();
'''
    before+='''        const hb_ir_instr_t* instr = &block->instrs[i];
        if (instr->op != HB_IR_STORE) return false;
        if (instr->src1.type != HB_OP_MEM || instr->src1.size != HB_SIZE_128) return false;
'''
    after=I.codegen(before);assert not invariants(before) and invariants(after)
    caught=[]
    for label,old in [('mov','    if (!instr || jit_evex_write_masked(instr)) return false;'),
                      ('pair','    if (jit_evex_write_masked(load) || jit_evex_write_masked(store)) return false;'),
                      ('load','                perepis_uchest(buf, 0, instr->src1.size, SH_POM_NE_REG);'),
                      ('loop','        if (jit_evex_write_masked(instr)) return false;'),
                      ('store','                perepis_uchest(buf, 1, instr->src1.size, SH_POM_NE_REG);')]:
        assert not invariants(after.replace(old,'/* deliberately removed */'));caught.append(label)
    rejects=[]
    for label,s in [('duplicate',before+I.MOV),('missing',before.replace(I.PAIR,'')),('already_patched',after)]:
        try:I.codegen(s)
        except ValueError:rejects.append(label)
        else:raise AssertionError('unsafe acceptance '+label)
    c='''#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
typedef struct {uint64_t target;} hb_ir_instr_t;
#define HB_EVEX_TARGET_PRESENT (1u<<28)
#define HB_EVEX_TARGET_MASK_SHIFT 24
'''+I.HELPER+'''int main(void){unsigned n=0;for(unsigned p=0;p<2;p++)for(unsigned z=0;z<2;z++)for(unsigned k=0;k<8;k++)for(unsigned arg=0;arg<1024;arg++){
 hb_ir_instr_t x={(p<<28)|(z<<27)|(k<<24)|arg};if(jit_evex_write_masked(&x)!=(p&&k))return 1;n++;}
 if(jit_evex_write_masked(NULL))return 1;printf("%u\\n",n);return 0;}
'''
    with tempfile.TemporaryDirectory() as td:
        td=Path(td);(td/'test.c').write_text(c);subprocess.run(['clang','-O2','-std=c11','-Wall','-Wextra',str(td/'test.c'),'-o',str(td/'test')],check=True)
        n=int(subprocess.check_output([str(td/'test')],text=True))
    a.out.parent.mkdir(parents=True,exist_ok=True);a.out.write_text(json.dumps(dict(scope='isolated predicate and anchored source transformations; NOT whole-HB emission',predicate_combinations=n,prepatch_invariant_fails=True,postpatch_invariant_passes=True,removed_exit_controls=caught,unsafe_inputs_rejected=rejects),indent=2));print('guard and installer tests passed')
if __name__=='__main__':main()
