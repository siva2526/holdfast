"""Loads the final-build evaluation results (audit/hf/results_final) for the paper builder."""
import csv, os, json, collections, statistics as st
R = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'eval', 'results', 'final')
def load(name):
    p = os.path.join(R, name)
    return list(csv.DictReader(open(p))) if os.path.exists(p) else []
CFGS = ['restore_only', 'redirect_only', 'holdfast', 'prov']
ATT = collections.defaultdict(list)
for c in CFGS:
    for r in load(f'attack_{c}.csv'):
        if not r.get('error'): ATT[(r['cfg'], r['corpus'], r['attack'])].append(r)
def cell(cfg, cor, atk):
    rs = ATT.get((cfg, cor, atk), [])
    if not rs: return None
    n = len(rs); det = sum(int(r['detected']) for r in rs)
    live = st.mean(int(r['live_intact']) / int(r['nfiles']) for r in rs)
    full = sum(int(r['live_intact']) == int(r['nfiles']) for r in rs)
    fin = st.mean(int(r['final_intact']) / int(r['nfiles']) for r in rs)
    dur = st.mean(int(r['durable_intact_no_recovery']) / int(r['nfiles']) for r in rs)
    ft = [int(r['files_touched_before_detect']) for r in rs if r['files_touched_before_detect'] not in ('', None)]
    alerts = [r for r in rs if r.get('alert_rollback_intact', '') != '']
    arec = sum(int(r['alert_rollback_intact']) == int(r['nfiles']) for r in alerts)
    return dict(n=n, det=det, live=live, full=full, fin=fin, dur=dur, ft=(st.median(ft) if ft else None), alerts=len(alerts), arec=arec, amb=sum(int(r['ambiguous_events']) > 0 for r in rs))
ATTACKS = sorted({k[2] for k in ATT})
def fp_suite(cfg, suite):
    rows = load(f'{suite}_{cfg}.csv')
    by = collections.defaultdict(list)
    for r in rows: by[r['workload']].append(r)
    frozen = sorted(w for w, v in by.items() if any(int(x['detections'] or 0) > 0 or x['error'] for x in v))
    trials = sum(len(v) for v in by.values()); ft = sum(1 for v in by.values() for x in v if int(x['detections'] or 0) > 0 or x['error'])
    deferred = sorted(w for w, v in by.items() if w not in frozen and any(x['verified_durable'] == '0' for x in v))
    return dict(workloads=sorted(by), frozen=frozen, trials=trials, frozen_trials=ft, deferred=deferred)
def wilson(k, n, z=1.96):
    if n == 0: return (0, 1)
    p = k / n; d = 1 + z * z / n; c = p + z * z / (2 * n); a = z * ((p * (1 - p) + z * z / (4 * n)) / n) ** 0.5
    return ((c - a) / d, (c + a) / d)
FP = {(c, s): fp_suite(c, s) for c in ('holdfast', 'prov', 'restore_only', 'redirect_only') for s in ('s1', 's2', 's3', 's4')}
def fp_total(cfg):
    ws = sum(len(FP[(cfg, s)]['workloads']) for s in ('s1', 's2', 's3', 's4')); fr = sum(len(FP[(cfg, s)]['frozen']) for s in ('s1', 's2', 's3', 's4'))
    tr = sum(FP[(cfg, s)]['trials'] for s in ('s1', 's2', 's3', 's4')); ft = sum(FP[(cfg, s)]['frozen_trials'] for s in ('s1', 's2', 's3', 's4'))
    return dict(workloads=ws, frozen=fr, trials=tr, frozen_trials=ft)
S5 = collections.defaultdict(list)
for r in load('s5.csv'): S5[(r['workload'], r['cfg'])].append(r)
ADA = [r for r in load('adaptive.csv') if not r.get('error')]
def release():
    p = os.path.join(R, 'release.json')
    return json.load(open(p)) if os.path.exists(p) else None
