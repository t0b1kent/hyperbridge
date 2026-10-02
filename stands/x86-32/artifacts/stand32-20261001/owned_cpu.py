"""Darwin CPU accounting for a Popen-owned process; no process enumeration."""
import ctypes,struct
LIB=ctypes.CDLL('/usr/lib/libproc.dylib',use_errno=True)
LIB.proc_pid_rusage.argtypes=[ctypes.c_int,ctypes.c_int,ctypes.c_void_p]
LIB.proc_pid_rusage.restype=ctypes.c_int
class Timebase(ctypes.Structure):
    _fields_=[('numer',ctypes.c_uint32),('denom',ctypes.c_uint32)]
TIMEBASE=Timebase()
SYSTEM=ctypes.CDLL('/usr/lib/libSystem.B.dylib')
if SYSTEM.mach_timebase_info(ctypes.byref(TIMEBASE)) or not TIMEBASE.denom:
    raise RuntimeError('Darwin timebase unavailable')

class OwnedCPU:
    def __init__(self,process):
        self.process=process;self.identity=None;self.samples=0
        self.initial=self.read()
    def read(self):
        # SDK rusage_info_v2: UUID[16], then eighteen uint64_t members;
        # user/system time use Mach ticks; proc_start_abstime is member8.
        # On this Apple Silicon host the measured timebase is 125/3, not 1.
        buf=ctypes.create_string_buffer(160)
        if LIB.proc_pid_rusage(self.process.pid,2,buf):
            raise OSError(ctypes.get_errno(),'owned proc_pid_rusage failed')
        # ri_uuid identifies the executable, not the process lifetime; an owned
        # shebang launcher may exec its interpreter without changing ownership.
        identity=struct.unpack_from('<Q',buf.raw,80)[0]
        if self.identity is not None and self.identity!=identity:raise RuntimeError('owned process identity changed')
        self.identity=identity;self.samples+=1
        user,system=struct.unpack_from('<QQ',buf.raw,16)
        return (user+system)*TIMEBASE.numer//TIMEBASE.denom
    def elapsed(self):return self.read()-self.initial
