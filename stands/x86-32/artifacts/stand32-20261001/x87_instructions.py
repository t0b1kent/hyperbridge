"""x87 encoding family, independent of incomplete Capstone FPU group tags."""
def is_x87(ins):
    # D8..DF escape opcodes are x87; 9B is the separate WAIT instruction.
    # Capstone opcode[] already excludes legacy prefixes.
    return 0xd8 <= ins.opcode[0] <= 0xdf or ins.opcode[0] == 0x9b

def memory_operand_size(ins,reported):
    """PE32 environment/save area sizes; Capstone labels FRSTOR as dword."""
    width16=0x66 in ins.prefix
    if ins.mnemonic in {'fldenv','fnstenv','fstenv'}:return 14 if width16 else 28
    if ins.mnemonic in {'frstor','fnsave','fsave'}:return 94 if width16 else 108
    return reported
