#!/usr/bin/env python3
"""Guarded patch installer for the 8a1020c hb_diff_case_runner.c.
Default: write a reviewable patch only. --apply creates an exclusive backup.
Never modifies the interpreter or any code generator.
"""
from pathlib import Path
import argparse,difflib,re,hashlib,json

EDITS=[
('snapshot MXCSR','    uint16_t x87_cw;','    uint32_t sse_mxcsr;\n    uint64_t sse_host_control, sse_host_status;\n    uint16_t x87_cw;'),
('extension header','static const hb_diff_nachalo_t* g_diff_nachalo;','static const hb_diff_nachalo_t* g_diff_nachalo;\n#include "hb_sse_oracle/runner_extension.h"'),
('seed hook','    hb_diff_nalozhit_nachalo(ctx, g_diff_nachalo);\n    return HB_OK;','    hb_diff_nalozhit_nachalo(ctx, g_diff_nachalo);\n    return hb_sse_apply(ctx);'),
('capture MXCSR','    s->arch = ctx->arch;','    s->arch = ctx->arch;\n    s->sse_mxcsr = ctx->mxcsr;\n    { hb_sse_host_state_t h = hb_sse_host_save();\n      s->sse_host_control = h.control; s->sse_host_status = h.status; }'),
('reset extension','        hb_diff_nachalo_t nachalo;','        hb_sse_reset();\n        hb_diff_nachalo_t nachalo;'),
('count token with named fields',"if (*rest && *rest != '#' && !strchr(rest, '='))", "if (*rest && *rest != '#' &&\n            strcspn(rest, \"= \\t\\r\\n\") == strcspn(rest, \" \\t\\r\\n\"))"),
('field parser','                if ((v = HB_DIFF_POLE("ожид-вид=")))','                int sse_field = hb_sse_parse(tok);\n                if (sse_field) {\n                    if (sse_field < 0) {\n                        printf("{\\\"ok\\\":false,\\\"error\\\":\\\"sse-field\\\"}\\n");\n                        pole_bad = 1;\n                    }\n                }\n                else if ((v = HB_DIFF_POLE("ожид-вид=")))'),
('field validation','        if (pole_bad) continue;','        if (!pole_bad && !hb_sse_validate()) {\n            printf("{\\\"ok\\\":false,\\\"error\\\":\\\"sse-version-or-input\\\"}\\n");\n            pole_bad = 1;\n        }\n        if (pole_bad) continue;'),
('absolute value checks','    bool ispolnen = (ri == HB_OK) && (interp_only || rj == HB_OK);','''    char sse_seed_diff[64] = {0}, sse_i_diff[64] = {0}, sse_j_diff[64] = {0};
    int sse_seed_ok = hb_sse_check_seed(&initial, sse_seed_diff, sizeof(sse_seed_diff));
    int sse_i_ok = hb_sse_check_value(&interp, sse_i_diff, sizeof(sse_i_diff));
    int sse_j_ok = interp_only ? 1 : hb_sse_check_value(&jit, sse_j_diff, sizeof(sse_j_diff));
    if (g_hb_sse.touched && (!sse_seed_ok || !sse_i_ok || !sse_j_ok)) {
        if (ok) snprintf(diff, sizeof(diff), "%s", !sse_seed_ok ? sse_seed_diff : !sse_i_ok ? sse_i_diff : sse_j_diff);
        ok = false;
    }
    bool ispolnen = (ri == HB_OK) && (interp_only || rj == HB_OK);'''),
('per-engine JSON','    print_snapshot_json("initial", &initial);','    hb_sse_json(&interp, &jit, sse_seed_ok, sse_i_ok, sse_j_ok, interp_only);\n    print_snapshot_json("initial", &initial);'),
('snapshot JSON','    printf(",\\\"data_at_1000\\\":\\\"");','''    printf(",\\\"mxcsr\\\":\\\"0x%04x\\\",\\\"host_fp_control\\\":\\\"0x%llx\\\",\\\"host_fp_status\\\":\\\"0x%llx\\\"",
           s->sse_mxcsr, (unsigned long long)s->sse_host_control, (unsigned long long)s->sse_host_status);
    printf(",\\\"data_at_1000\\\":\\\"");'''),
('line capacity','    char line[1024];','    char line[8192];'),
('line truncation','    while (fgets(line, sizeof(line), stdin)) {','''    while (fgets(line, sizeof(line), stdin)) {
        if (!strchr(line, '\\n') && !feof(stdin)) {
            int ch; while ((ch = getchar()) != '\\n' && ch != EOF) {}
            printf("{\\\"ok\\\":false,\\\"error\\\":\\\"line-too-long\\\"}\\n");
            continue;
        }'''),
]

def transform(s):
 for label,old,new in EDITS:
  count=s.count(old)
  if count!=1:raise ValueError(f'{label}: expected one source anchor, found {count}; refusing partial patch')
  s=s.replace(old,new,1)
 # Preserve the thread's original FP environment across each engine run. Both
 # backends enter through init_context and the SAME explicit MXCSR seed hook.
 m=re.search(r'static hb_result_t run_backend\((.*?)\)\s*\{',s,re.S)
 if not m:raise ValueError('run_backend signature missing')
 signature=m.group(1)
 names=[re.search(r'(\w+)\s*$',x).group(1) for x in signature.split(',')]
 original=m.group(0);s=s.replace(original,original.replace('run_backend(', 'run_backend_sse_inner(',1),1)
 marker='static const char* reg_name('
 if s.count(marker)!=1:raise ValueError('backend wrapper anchor')
 wrapper='static hb_result_t run_backend('+signature+') {\n    hb_sse_host_state_t old = hb_sse_host_save();\n    hb_result_t r = run_backend_sse_inner('+', '.join(names)+');\n    hb_sse_host_restore(old);\n    return r;\n}\n'
 s=s.replace(marker,wrapper+marker,1)
 return s

def main():
 a=argparse.ArgumentParser();a.add_argument('--repo',type=Path,default=Path(__file__).resolve().parents[2]);a.add_argument('--apply',action='store_true');args=a.parse_args()
 p=args.repo/'tests/hb_diff_case_runner.c';raw=p.read_bytes();old=raw.decode();new=transform(old)
 patch=''.join(difflib.unified_diff(old.splitlines(True),new.splitlines(True),fromfile='a/tests/hb_diff_case_runner.c',tofile='b/tests/hb_diff_case_runner.c'))
 out=Path(__file__).parent/'out';out.mkdir(exist_ok=True);(out/'runner-extension.patch').write_text(patch)
 if args.apply:
  backup=p.with_name(p.name+'.pre-sse-oracle');backup.open('xb').write(raw);p.write_text(new)
 print(json.dumps({'source_sha256':hashlib.sha256(raw).hexdigest(),'patched_sha256':hashlib.sha256(new.encode()).hexdigest(),'patch':str(out/'runner-extension.patch'),'applied':args.apply}))
if __name__=='__main__':main()
