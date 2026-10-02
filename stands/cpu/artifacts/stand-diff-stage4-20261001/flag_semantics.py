"""Architecturally undefined arithmetic flags, covering scalar logical siblings.

Capstone 5.0.7 returns eflags=0 for REX TEST r/m8,r8 (44 84 62 24),
so metadata alone incorrectly compares AF. AND/OR/XOR/TEST define the five
other arithmetic flags and leave AF undefined for every scalar operand width.
"""


def scalar_logic_mask(mnemonic, undefined):
    if mnemonic.split()[-1] in {'test', 'and', 'or', 'xor'}:
        return (undefined & ~0x8d5) | 0x10
    return undefined
