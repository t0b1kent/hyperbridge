from ctypes import *
from pathlib import Path
import os,platform
class Sample(Structure):
 _fields_=[('x',(c_ubyte*32)*3),('mem',c_ubyte*32),('rax',c_uint64),('flags',c_uint64),('mxcsr',c_uint32),('pad',c_uint32)]
class Result(Structure):
 _fields_=[('x',c_ubyte*32),('rax',c_uint64),('flags',c_uint64),('host_mxcsr',c_uint32),('guest_mxcsr',c_uint32),('status',c_int32),('reads',c_uint32)]
def load():
 if platform.system()!='Linux' or platform.machine()!='x86_64':
  raise RuntimeError('Native oracle requires Linux x86-64. Use exported .cases on ARM64.')
 if ' avx ' not in ' '+Path('/proc/cpuinfo').read_text().replace('\n',' ')+' ':
  raise RuntimeError('This corpus also uses AVX/YMM and requires OS-enabled AVX.')
 l=CDLL(os.environ.get('HB_SSE_LIB',str(Path(__file__).resolve().parent/'out/libhb_sse_oracle.so')))
 l.oracle_prepare.argtypes=[c_void_p,c_uint];l.oracle_prepare.restype=c_void_p
 l.oracle_error.restype=c_char_p
 l.oracle_ir_count.argtypes=[c_void_p];l.oracle_ir_count.restype=c_uint
 l.oracle_ir_opcode.argtypes=[c_void_p];l.oracle_ir_opcode.restype=c_uint
 l.oracle_run.argtypes=[c_void_p,POINTER(Sample),c_uint,POINTER(Result)]
 return l
