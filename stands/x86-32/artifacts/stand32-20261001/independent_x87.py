"""Small integer-only architectural witnesses; no FEX/Unicorn arithmetic."""
PUSHES={'fld','fild','fbld','fld1','fldl2t','fldl2e','fldpi','fldlg2','fldln2','fldz'}
CLEAR_OR_RESTORE={'fclex','fnclex','finit','fninit','fsave','fnsave','fldenv','frstor','fxrstor','xrstor'}
INDEFINITE80='00000000000000c0ffff'

def tag(raw80,occupied=True):
    if not occupied:return 3
    value=int.from_bytes(bytes.fromhex(raw80),'little')
    exponent=(value>>64)&0x7fff;significand=value&((1<<64)-1)
    if exponent==0 and significand==0:return 1
    if 0<exponent<0x7fff and significand&(1<<63):return 0
    return 2

def masked_push_overflow(event):
    """Intel masked x87 stack-overflow rule: IE/SF/C1, push indefinite."""
    if event['mnemonic'] not in PUSHES or not event['fcw']&1:return None
    destination=((event['fsw']>>11)-1)&7
    if event['ftw']>>(2*destination)&3==3:return None
    after=event['after'];mask=0x241
    return dict(rule='masked x87 push to occupied physical register',destination=destination,
                expected_fsw_mask=mask,actual_fsw_mask=after['fsw']&mask,
                expected_top=destination,actual_top=after['fsw']>>11&7,
                expected_raw80=INDEFINITE80,actual_raw80=after['fp80'][destination],
                reference_violates_rule=(after['fsw']&mask)!=mask or after['fp80'][destination]!=INDEFINITE80)

def sticky_ie_witness(initial_fsw,trace,reference_fsw,native_fsw):
    if not initial_fsw&1 or any(row[2] in CLEAR_OR_RESTORE for row in trace):return None
    return dict(rule='IE remains set until explicit exception clear, init, or environment restore',
                input_ie=1,expected_ie=1,reference_ie=reference_fsw&1,native_ie=native_fsw&1,
                engine_violates_rule=not bool(native_fsw&1))

def pop_mask(abridged_ftw,top):return abridged_ftw&~(1<<(top&7))

def environment_pointers(raw, size):
    """Protected-mode 14/28-byte x87 environment, integer fields only."""
    if size not in (14,28) or len(raw)<size:raise ValueError('short x87 environment')
    width=size//7
    def get(offset,count):return int.from_bytes(raw[offset:offset+count],'little')
    fields={'fip':(3*width,width),'cs':(4*width,2),
            'fdp':(5*width,width),'ds':(6*width,2)}
    if width==4:fields['fop']=(18,2)
    values={k:get(*v) for k,v in fields.items()}
    if 'fop' in values:values['fop']&=0x7ff
    return fields,values

def environment_restore_witness(ref,got,diff):
    """Admit only a complete restore->save pair with every other byte equal.

    Arithmetic, extra instructions, sparse hash-only output, and an unrecorded
    field are deliberately outside this proof. Raw oracle/native bytes survive.
    """
    events=ref.get('x87_events',[])
    if len(events)!=2 or len(ref.get('trace',[]))!=2:return None
    restore,save=events
    if restore['mnemonic'] not in {'fldenv','frstor'} or save['mnemonic'] not in {'fnstenv','fstenv','fnsave','fsave'}:return None
    if len(restore.get('memory',[]))!=1 or len(save.get('memory',[]))!=1:return None
    incoming=restore['memory'][0];destination=save['memory'][0]
    if 'bytes' not in incoming:return None
    # In this PE32 protected-mode witness, 66 selects the 16-bit environment.
    def size(event):
        operand16=False
        for byte in bytes.fromhex(event['code']):
            if byte not in {0xf0,0xf2,0xf3,0x2e,0x36,0x3e,0x26,0x64,0x65,0x66,0x67}:break
            if byte==0x66:operand16=True
        return 14 if operand16 else 28
    try:_,loaded=environment_pointers(bytes.fromhex(incoming['bytes']),size(restore))
    except ValueError:return None
    address=destination['address'];page=address&~0x3fff
    key={0x20000000:'data',0x21000000:'stack'}.get(page)
    if key is None or set(diff)!={key} or key not in got:return None
    reference=bytes.fromhex(ref.get('memory',{}).get(hex(page),''));native=bytes.fromhex(got[key])
    offset=address-page;output_size=size(save)
    if len(reference)!=16384 or len(native)!=len(reference) or offset+output_size>len(reference):return None
    fields,reference_values=environment_pointers(reference[offset:],output_size)
    _,native_values=environment_pointers(native[offset:],output_size)
    corrected=bytearray(reference);expected={};unverified=[]
    for field,(position,width) in fields.items():
        if field not in loaded:unverified.append(field);continue
        mask=0x7ff if field=='fop' else (1<<(width*8))-1
        expected[field]=loaded[field]&mask
        if native_values[field]!=expected[field]:return None
        start=offset+position
        prior=int.from_bytes(corrected[start:start+width],'little')
        corrected[start:start+width]=((prior&~mask)|expected[field]).to_bytes(width,'little')
    if bytes(corrected)!=native or native==reference:return None
    return dict(rule='FLDENV/FRSTOR restores protected-mode pointers; immediate FNSTENV/FNSAVE returns them',
        expected=expected,reference=reference_values,native=native_values,
        reference_violates_rule=True,native_matches_loaded_fields=True,all_other_output_bytes_equal=True,
        unverified_fields=unverified,hardware_oracle='NOT_ENABLED',
        evidence='artifacts/guest32-base-20261001/stage3-x87-env-restores/RESULT.json')
