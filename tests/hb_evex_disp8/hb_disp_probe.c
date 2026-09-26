/* Читает строки hex, декодирует ОДНУ инструкцию декодером HB, печатает
 * "ok <len> <opcode> <evex> <disp|none> <memsize>" или "err <rc>". */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "hb_decoder.h"
int main(int argc,char**argv){int a32=argc>1&&argv[1][0]==0x33;
  char line[512];uint8_t b[64];
  while(fgets(line,sizeof line,stdin)){
    size_t n=0;for(char*p=line;p[0]&&p[1]&&n<sizeof b;p+=2){unsigned v;if(sscanf(p,"%2x",&v)!=1)break;b[n++]=(uint8_t)v;}
    hb_decoder_t*d=hb_decoder_create(a32?HB_ARCH_X86:HB_ARCH_X64,b,n,0x10000);hb_decoded_t o;memset(&o,0,sizeof o);
    hb_result_t rc=hb_decode_next(d,&o);
    if(rc!=HB_OK){printf("err %d\n",rc);}
    else{
      const char*ds="none";char buf[64];int ms=0;
      if(o.op1.present&&o.op1.is_mem){snprintf(buf,sizeof buf,"%lld",(long long)o.op1.mem.disp);ds=buf;ms=o.op1.size;}
      else if(o.op2.present&&o.op2.is_mem){snprintf(buf,sizeof buf,"%lld",(long long)o.op2.mem.disp);ds=buf;ms=o.op2.size;}
      else if(o.op3.present&&o.op3.is_mem){snprintf(buf,sizeof buf,"%lld",(long long)o.op3.mem.disp);ds=buf;ms=o.op3.size;}
      printf("ok %u %d %d %s %d\n",o.len,(int)o.opcode,(int)o.evex,ds,ms);
    }
    fflush(stdout);hb_decoder_destroy(d);
  }
  return 0;
}
