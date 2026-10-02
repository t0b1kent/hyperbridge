"""Persistent native workers; the same reference state feeds both guest bases."""
import atexit,collections,concurrent.futures,hashlib,json,os,pathlib,queue,signal,subprocess,sys,threading,time
import stand32 as s
import evidence_io as io
import memory_store as ms
import known_defects as known
from owned_cpu import OwnedCPU
OWN=pathlib.Path(__file__).resolve().parent
SESSIONS={};REGISTRY=None;CONFIG=None
class GateBudgetExceeded(Exception):pass
def gate_budget_signal(sig,frame):raise GateBudgetExceeded()

def state_digest(state,reference=False):
    keys=['status','state_valid','regs','rip','rflags','mxcsr','fcw','fsw','ftw','fp80','xmm','segments',
          'x87_raw','x87_fsw','x87_abridged_ftw','x87_reduced','memory_sha256','memory_page_sha256','data','stack']
    projection={k:state[k] for k in keys if k in state}
    return hashlib.sha256(json.dumps(projection,sort_keys=True,separators=(',',':')).encode()).hexdigest()

class NativeSession:
    def __init__(self,runner,base,out,mutation='',cpu_budget_ms=2000,deadline=None):
        self.runner=str(pathlib.Path(runner).resolve());self.base=base;self.out=pathlib.Path(out);self.mutation=mutation
        self.cpu_budget_ms=cpu_budget_ms
        self.deadline=deadline
        self.process=None;self.serial=0;self.q=None;self.stderr=None;self.reader=None
    def stop(self):
        p=self.process
        if p:
            if p.poll() is None:
                p.stdin.close()
                try:p.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    p.terminate();p.send_signal(signal.SIGCONT)
                    try:p.wait(timeout=3)
                    except subprocess.TimeoutExpired:p.kill();p.wait(timeout=3)
            if self.reader:
                self.reader.join(timeout=3)
                if self.reader.is_alive():raise RuntimeError('owned stdout drain FAILED')
            p.stdout.close()
            self.stderr.close()
        self.process=None
    def start(self):
        self.stop();self.serial+=1;self.q=queue.Queue()
        env=dict(os.environ,STAND32_GUEST_BASE=self.base,STAND32_MUTATION=self.mutation,FEX_MULTIBLOCK='0',FEX_TSOENABLED='0',
                 FEX_MAXINST='256',FEX_X87REDUCEDPRECISION='0',ORACLE_TIMEOUT_MS='0',ORACLE_NO_FENCE='1')
        self.stderr=(self.out/f'native-{os.getpid()}-{self.base}-{self.serial}.stderr').open('wb')
        self.process=subprocess.Popen([self.runner],env=env,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=self.stderr,bufsize=0,start_new_session=True)
        stream=self.process.stdout;q=self.q
        def read():
            try:
                for line in iter(stream.readline,b''):q.put(line)
            finally:q.put(None)
        self.reader=threading.Thread(target=read,daemon=True);self.reader.start()
    def execute(self,line):
        if self.process is None or self.process.poll() is not None:self.start()
        started=time.monotonic();raw=[];got={};watchdog=False;cpu_hit=False;counter_error=None;gate_hit=False
        process=self.process;pid=process.pid;cpu_ns=0;counter=None;native_terminal_status=None
        budget=dict(kind='owned_process_cpu_user_plus_system',milliseconds=self.cpu_budget_ms,
            poll_milliseconds=25,internal_timer_milliseconds=0)
        try:
            counter=OwnedCPU(self.process)
            self.process.stdin.write(line.encode());self.process.stdin.flush()
            while True:
                try:item=self.q.get(timeout=.025)
                except queue.Empty:item=b''
                if item:
                    raw.append(item)
                    if item.startswith(b'{'):
                        got=json.loads(item);native_terminal_status=got.get('status')
                cpu_ns=counter.elapsed()
                if self.deadline is not None and time.monotonic()>=self.deadline:
                    gate_hit=True;self.process.terminate();break
                if cpu_ns>=self.cpu_budget_ms*1000000:
                    cpu_hit=True;self.process.terminate();break
                if time.monotonic()-started>=30:
                    watchdog=True;self.process.terminate();break
                if item==b'':continue
                if item is None:break
                if got:break
        except (OSError,RuntimeError) as exc:
            counter_error=repr(exc)
            if self.process.poll() is None:self.process.terminate()
        rc=self.process.poll()
        if watchdog or cpu_hit or gate_hit or counter_error or not got:
            self.stop()
            rc=process.returncode
            # Preserve any terminal bytes enqueued while the owned child stopped.
            while True:
                try:item=self.q.get_nowait()
                except queue.Empty:break
                if item:raw.append(item)
            got={'status':'GATE_BUDGET_EXHAUSTED' if gate_hit else 'timeout' if cpu_hit else 'HARNESS_WALL_WATCHDOG' if watchdog else
                 'HARNESS_CPU_COUNTER_FAILED' if counter_error else 'NATIVE_PROCESS_EXIT','state_valid':False}
        return got,0 if rc is None else rc,b''.join(raw),dict(pid=pid,seconds=time.monotonic()-started,watchdog=watchdog,
            cpu_nanoseconds=cpu_ns,cpu_samples=counter.samples if counter else 0,cpu_budget_hit=cpu_hit,
            cpu_counter_error=counter_error,native_terminal_status=native_terminal_status,enforced_execution_limit=budget,gate_budget_hit=gate_hit)

def close_sessions():
    for session in SESSIONS.values():session.stop()
    SESSIONS.clear()

def initialize(config):
    global CONFIG,REGISTRY
    CONFIG=config;REGISTRY=known.load(config.get('known'))
    os.environ['TMPDIR']=str(OWN/'tmp')
    if config['nice']>os.getpriority(os.PRIO_PROCESS,0):os.nice(config['nice']-os.getpriority(os.PRIO_PROCESS,0))
    atexit.register(close_sessions)

def write_pages(path,pages):
    import struct
    with path.open('xb') as f:
        f.write(b'HBPAGES1'+struct.pack('<Q',len(pages)))
        for address,raw in pages:f.write(struct.pack('<Q',address));f.write(raw)

def pair(job):
    case=job['case'];out=pathlib.Path(CONFIG['out'])/job['label'];out.mkdir(exist_ok=True)
    prefix=out/f'{case["id"]:06d}';started=time.monotonic()
    deadline=CONFIG.get('deadline');old_handler=None
    try:
        if deadline is not None:
            if time.monotonic()>=deadline:raise GateBudgetExceeded()
            old_handler=signal.signal(signal.SIGALRM,gate_budget_signal)
            signal.setitimer(signal.ITIMER_REAL,max(.001,deadline-time.monotonic()))
        ref=s.oracle(case,sparse=CONFIG.get('sparse',True))
    except GateBudgetExceeded:ref=dict(status='GATE_BUDGET_EXHAUSTED')
    except Exception as exc:ref=dict(status='REFERENCE_SETUP_FAILED',error=repr(exc))
    finally:
        if old_handler is not None:
            signal.setitimer(signal.ITIMER_REAL,0);signal.signal(signal.SIGALRM,old_handler)
    reference_seconds=time.monotonic()-started
    io.write_json(prefix.with_suffix('.reference.json'),ref)
    # Source file is immutable and contains every original bit of the case.
    io.write_json(prefix.with_suffix('.source.json'),dict(cases=job['source'],id=case['id'],fingerprint=known.fingerprint(case)))
    rows=[];expanded=None
    if ref['status']=='exit' and case.get('pages'):
        expanded=prefix.with_suffix('.temporary.pages')
        if ref.get('sparse_input_pages') is not None:
            write_pages(expanded,[(a,ms.read_object(h)) for a,h in ref['sparse_input_pages']])
        else:ms.expand(case['pages'],expanded)
    try:
        for base in job['bases']:
            row=dict(id=case['id'],name=case['name'],origin=case['origin'],label=job['label'],base=base,
                     source=job['source'],source_sha256=known.fingerprint(case),reference=str(prefix.with_suffix('.reference.json')),
                     reference_state_sha256=state_digest(ref,True),diff={})
            if ref['status']!='exit':
                row['classification']=ref['status'];got={}
            else:
                key=(base,CONFIG['runner'],CONFIG.get('mutation',''))
                if key not in SESSIONS:SESSIONS[key]=NativeSession(CONFIG['runner'],base,pathlib.Path(CONFIG['out']),CONFIG.get('mutation',''),deadline=deadline)
                session=SESSIONS[key];attempts=[];line=s.native_line(case,expanded)
                for attempt in range(2):
                    if attempt:session.stop() # one fresh, singleton retry; raw first outcome retained
                    got,rc,raw,telemetry=session.execute(line)
                    rawpath=prefix.with_suffix('.'+base+f'.attempt{attempt+1}.stdout')
                    rawpath.write_bytes(raw)
                    if len(raw)>=32768:io.pack_existing(rawpath)
                    diff=s.compare(ref,got,rc);classification=s.native_classification(diff,got,rc,'')
                    attempts.append(dict(status=got.get('status'),rc=rc,classification=classification,diff=diff,stdout=str(rawpath),
                        state_sha256=state_digest(got),execution_limit=telemetry['enforced_execution_limit'],**telemetry))
                    if got.get('status')!='timeout':break
                row.update(classification=classification,diff=diff,attempts=attempts)
                if len(attempts)==2:session.stop() # retry is never a reused batch process
            original=row['classification']
            classification,family,verdict,witness=s.adjudicate_case(case,ref,got,row)
            row.update(raw_classification=original,classification=classification,family=family,verdict=verdict,witness=witness)
            if CONFIG.get('admit_known',True):known.apply(case,row,REGISTRY)
            row['reproduction']=f'python3 {OWN}/stage2/replay.py --runner {CONFIG["runner"]} --cases {job["source"]!r} --case-id {case["id"]} --base {base} --out {OWN}/out/repro-stage2-{time.time_ns()}'
            row['timing']=dict(reference_seconds=reference_seconds,total_seconds=time.monotonic()-started)
            rows.append(row)
    finally:
        if expanded:expanded.unlink(missing_ok=True)
    return rows

def canonical(rows):
    # Runtime PIDs/PCs/timing/raw attempt files stay in raw evidence. The semantic
    # projection contains every compared value, outcome, source identity and retry.
    clean=[]
    for row in rows:
        item={k:row.get(k) for k in ['label','id','base','classification','raw_classification','family','diff','known_entry','source_sha256','reference_state_sha256']}
        item['attempts']=[{k:a.get(k) for k in ['status','rc','classification','diff','watchdog','state_sha256','execution_limit']} for a in row.get('attempts',[])]
        clean.append(item)
    clean.sort(key=lambda x:(x['label'],x['id'],x['base']))
    return (json.dumps(clean,sort_keys=True,separators=(',',':'))+'\n').encode()

def replay(jobs,runner,out,workers=4,*,sparse=True,admit_known=True,mutation='',nice=5,deadline=None):
    out=pathlib.Path(out);out.mkdir(parents=True,exist_ok=False);start=time.monotonic()
    config=dict(runner=str(pathlib.Path(runner).resolve()),out=str(out),nice=nice,sparse=sparse,admit_known=admit_known,mutation=mutation,deadline=deadline)
    rows=[]
    with concurrent.futures.ProcessPoolExecutor(max_workers=workers,initializer=initialize,initargs=(config,)) as pool:
        for group in pool.map(pair,jobs,chunksize=8):rows.extend(group)
    semantic=canonical(rows);(out/'semantic.json').write_bytes(semantic)
    counts=dict(collections.Counter(r['classification'] for r in rows))
    report=dict(status='MEASURED',seconds=time.monotonic()-start,workers=workers,nice=nice,runner=str(runner),runner_sha256=s.sha(runner),
                planned=sum(len(j['bases']) for j in jobs),executed=sum(r['classification']!='GATE_BUDGET_EXHAUSTED' for r in rows),
                processed=len(rows),native_attempts=sum(len(r.get('attempts',[])) for r in rows),
                skipped_gate_budget=sum(r['classification']=='GATE_BUDGET_EXHAUSTED' for r in rows),counts=counts,results=rows,
                semantic_sha256=hashlib.sha256(semantic).hexdigest(),limits=dict(
                    native_budget_kinds=dict(collections.Counter(a['execution_limit']['kind'] for r in rows for a in r.get('attempts',[]))),
                    emergency_watchdog='30s wall; HARNESS_WALL_WATCHDOG never equality',reference='1000000 guest instructions'))
    io.write_json(out/'RESULT.json',report)
    return report
