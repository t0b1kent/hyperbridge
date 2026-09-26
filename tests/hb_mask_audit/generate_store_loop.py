#!/usr/bin/env python3
"""Native x86 witnesses for the 8xSTORE128 semantic loop shortcut.
Uses the HBUP0002 generator. Does not claim that a particular HyperBridge run
selects the hot two-block helper: matcher selection is a separate regression.
"""
import generate


def loop_forms():
    result = []
    specifications = [(0, -1), (0, -2)]
    specifications += [(k, slot) for k in range(1, 8) for slot in range(8)]
    specifications += [(k, 8) for k in range(1, 8)]
    for k, slot in specifications:
        stores = []
        for i in range(8):
            suffix = f'{{k{k}}}' if k and (slot == 8 or slot == i) else ''
            prefix = '' if slot == -1 else '{evex} '
            stores.append(f'{prefix}vmovups [rcx+{16*i}]{suffix},xmm1')
        body = '\n'.join(['mov rcx,rdi', 'mov r8d,128', '1:', *stores,
                          'add rcx,128', 'sub r8,128', 'cmp r8,128', 'jae 1b'])
        name = (f'LOOP8-k{k}-slot{slot}' if k else
                'LOOP8-CTRL-' + ('vex' if slot == -1 else 'evex-aaa0'))
        result.append(dict(name=name, asm=body, vl=128, lane=4, k=k,
                           z=False, kind='normal', mode=0, valid=0))
    return result


if __name__ == '__main__':
    generate.forms = loop_forms
    raise SystemExit(generate.main())
