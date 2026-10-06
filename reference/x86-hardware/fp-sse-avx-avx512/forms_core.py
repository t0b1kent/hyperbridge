# Original MacRunner hardware reference generator. MIT License.
def forms():
    fs=[]
    def add(cls,name,enc,width,lane,scalar,nops,axes,asm,**kw):
        fs.append(dict(cls=cls,name=name,enc=enc,width=width,lane=lane,scalar=scalar,nops=nops,axes=axes,asm=asm,feature='avx' if enc=='VEX' else 'sse2',**kw))
    for op in ('add','sub','mul','div','sqrt','min','max'):
      for suf in ('ps','pd','ss','sd'):
        scalar=suf[0]=='s'; lane=4 if suf[-1]=='s' else 8
        add('arithmetic',op+suf,'SSE',128,lane,scalar,2,[1] if op=='sqrt' else [0,1],f'{op+suf} %xmm1, %xmm0')
        for width in ((128,) if scalar else (128,256)):
          r='xmm' if width==128 else 'ymm'; name='v'+op+suf
          unary=op=='sqrt' and not scalar
          add('arithmetic',name,'VEX',width,lane,scalar,2 if unary else 3,[1] if unary else [1,2],f'{name} %{r}1, %{r}0' if unary else f'{name} %{r}2, %{r}1, %{r}0')
    for op in ('fmadd','fmsub','fnmadd','fnmsub','fmaddsub','fmsubadd'):
      for order in ('132','213','231'):
       for suf in (('ps','pd') if op in ('fmaddsub','fmsubadd') else ('ps','pd','ss','sd')):
        scalar=suf[0]=='s';lane=4 if suf[-1]=='s' else 8
        for width in ((128,) if scalar else (128,256)):
          r='xmm' if width==128 else 'ymm';name='v'+op+order+suf
          add('fma',name,'VEX',width,lane,scalar,3,[0,1,2],f'{name} %{r}2, %{r}1, %{r}0')
          fs[-1]['feature']='fma'
    for enc in ('SSE','VEX'):
      for suf in ('ps','pd','ss','sd'):
       scalar=suf[0]=='s';lane=4 if suf[-1]=='s' else 8
       for width in ((128,) if scalar or enc=='SSE' else (128,256)):
        for imm in range(8 if enc=='SSE' else 32):
          r='xmm' if width==128 else 'ymm';name=('v' if enc=='VEX' else '')+'cmp'+suf
          add('comparison',name,enc,width,lane,scalar,2 if enc=='SSE' else 3,[0,1] if enc=='SSE' else [1,2],f'{name} ${imm}, %{r}1, %{r}0' if enc=='SSE' else f'{name} ${imm}, %{r}2, %{r}1, %{r}0',imm=imm)
      for op in ('comis','ucomis'):
       for suf in ('s','d'):
        name=('v' if enc=='VEX' else '')+op+suf
        add('comparison',name,enc,128,4 if suf=='s' else 8,True,2,[0,1],f'{name} %xmm1, %xmm0',flags=True,out_bytes=2)
    for op in ('rcp','rsqrt'):
      for scalar in (False,True):
       suf='ss' if scalar else 'ps';name=op+suf
       add('approximation',name,'SSE',128,4,scalar,2,[1],f'{name} %xmm1, %xmm0')
       for width in ((128,) if scalar else (128,256)):
        r='xmm' if width==128 else 'ymm';name='v'+op+suf
        add('approximation',name,'VEX',width,4,scalar,3 if scalar else 2,[1,2] if scalar else [1],f'{name} %{r}2, %{r}1, %{r}0' if scalar else f'{name} %{r}1, %{r}0')
    return fs
