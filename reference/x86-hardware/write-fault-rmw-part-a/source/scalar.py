# SPDX-License-Identifier: MIT

def forms():
    fs=[]
    def add(name,w,code,**kw): fs.append(dict(name=name,width=w,code=code,legal=True,**kw))
    for w in [1,2,4,8]:
        p='66' if w==2 else '48' if w==8 else ''
        add(f'mov{w*8}_reg',w,p+('881f' if w==1 else '891f'))
        imm={1:'a5',2:'a5b6',4:'a5b6c7d8',8:'a5b6c7d8'}[w]
        add(f'mov{w*8}_imm',w,p+('c607' if w==1 else 'c707')+imm)
        for direction in [0,1]:
            for op in ['stos','movs']:
                for count in [0,1,2,3,4]:
                    # count=0 means the unprefixed, single-element instruction.
                    pre=('f3' if count else '')+p
                    opc={'stos':('aa' if w==1 else 'ab'),'movs':('a4' if w==1 else 'a5')}[op]
                    add(f'{"rep_" if count else ""}{op}{w*8}_df{direction}_n{count or 1}',w,pre+opc,string=True,count=count or 1,df=direction,regs={'rcx':count or 1})
    for w in [4,8]: add(f'movnti{w*8}',w,('48' if w==8 else '')+'0fc31f',feature='sse2')
    for w in [2,8]:
        p='66' if w==2 else ''
        add(f'push{w*8}_reg',w,p+'53',stack=True)
        add(f'push{w*8}_imm8',w,p+'6ac3',stack=True)
        add(f'push{w*8}_immfull',w,p+'68'+('a5b6' if w==2 else 'a5b6c7d8'),stack=True)
        add(f'push{w*8}_mem',w,p+'ff36',stack=True)
    add('call_rel32',8,'e800000000',stack=True,call=True)
    return fs
