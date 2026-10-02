"""Manual acceptance list. A family rule alone never admits an unseen case."""
import hashlib,json,pathlib
import evidence_io
import memory_store
OWN=pathlib.Path(__file__).resolve().parent

def diff_fingerprint(diff):
    return hashlib.sha256(json.dumps(diff,sort_keys=True,separators=(',',':')).encode()).hexdigest()

def fingerprint(case):
    if not isinstance(case.get('code'),str) or not case['code']:
        raise ValueError('known fingerprint requires a case with code, not a source pointer')
    payload={k:case[k] for k in ['code','state','seed','patches'] if k in case}
    if case.get('pages'):
        index=memory_store.index_path(case['pages'])
        if memory_store.has_index(case['pages']):
            image=memory_store.read_index(case['pages']);payload['image_sha256']=image.get('uncompressed_sha256',image.get('manifest_sha256'))
        else:
            h=hashlib.sha256()
            for a,b in memory_store.read_pages(case['pages']):h.update(a.to_bytes(8,'little'));h.update(b)
            payload['image_sha256']=h.hexdigest()
    return hashlib.sha256(json.dumps(payload,sort_keys=True,separators=(',',':')).encode()).hexdigest()

def load(path=None):
    data=json.loads(pathlib.Path(path or OWN/'known-defects.json').read_text())
    if data['schema']!=1:raise ValueError('known registry version')
    by_case={};reviewed={}
    for entry in data['entries']:
        for key in ['case_sha256','class','defect_owner','lane','date','link','diff_keys']:
            if not entry.get(key):raise ValueError('incomplete manual known entry: '+key)
        if entry['case_sha256'] in by_case:raise ValueError('duplicate known case')
        source=entry.get('review_source');expected=entry.get('review_source_sha256')
        if not source or not expected:raise ValueError('known entry lacks pinned manual review')
        if source not in reviewed:
            if evidence_io.sha(source)!=expected:raise ValueError('manual review source drift')
            report=evidence_io.read_json(source);allowed={}
            for family in {'F03_POP_TAG','F04_STICKY_IE','F06_SERIALIZED_TAG','F07_DEFERRED_AF_REP_MOVS','R03_REP_MOVS_LAZY_MEMORY_AF'}:
                for row in report['classes'].get(family,[]):
                    key=fingerprint(evidence_io.read_json(row['input_state']))
                    allowed.setdefault((key,family),set()).add(diff_fingerprint(row['diff']))
            reviewed[source]=(expected,allowed)
        digest,allowed=reviewed[source]
        if digest!=expected:raise ValueError('conflicting review source hash')
        entry['diff_sha256']=sorted(allowed.get((entry['case_sha256'],entry['class']),set()))
        if not entry['diff_sha256']:raise ValueError('manual case has no reviewed exact delta')
        if entry.get('result_class','KNOWN') not in ('KNOWN','REFERENCE_GAP'):
            raise ValueError('invalid manual result class')
        by_case[entry['case_sha256']]=entry
    return by_case

def apply(case,row,registry):
    entry=registry.get(fingerprint(case));classification=row['classification']
    if classification=='REFERENCE_INSN_GAP':
        row.update(classification='REFERENCE_GAP',family='UNICORN_UNSUPPORTED_INSTRUCTION',verdict='пробел эталона; raw Unicorn invalid-instruction retained')
        return row
    # No post-block path is invented: F02 observability is audited separately
    # from entrypoints/recorded instruction spans, and its verdict remains scoped.
    if row.get('family')=='F02_EMPTY_RAW80':
        row.update(classification='EMPTY_RAW80',verdict='отдельный класс; наблюдаемость в F02-CORPUS.json')
        return row
    if row.get('family')=='ENVIRONMENT_INPUT':
        row.update(classification='REFERENCE_GAP',verdict='пробел эталона: внешнее окружение не записано')
        return row
    if classification in ('KNOWN','NEW'):
        if entry and row.get('family') in (entry['class'],'UNCLASSIFIED') and set(row.get('diff',{}))==set(entry['diff_keys']) and diff_fingerprint(row.get('diff',{})) in entry['diff_sha256']:
            row.update(classification=entry.get('result_class','KNOWN'),family=entry['class'],known_entry=entry['case_sha256'])
            if entry.get('result_class')=='REFERENCE_GAP':
                row['verdict']='пробел эталона; точный вход и дельта разобраны вручную'
        elif classification=='KNOWN':
            row.update(classification='NEW',known_admission='NOT_IN_MANUAL_LIST')
    elif classification=='EQUAL' and entry:
        # Agreement with a documented bad reference must not become EQUAL or
        # an engine FIXED claim. Retiring a reference gap requires manual review.
        result_class='REFERENCE_GAP' if entry.get('result_class')=='REFERENCE_GAP' else 'FIXED'
        row.update(classification=result_class,known_entry=entry['case_sha256'],family=entry['class'])
        if result_class=='REFERENCE_GAP':row['verdict']='совпадение с известным пробелом эталона; требуется ручной пересмотр'
    return row
