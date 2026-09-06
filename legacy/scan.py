#!/usr/bin/env python3
"""face-match scan: margin-based reference audit + cluster scoring. Read-only."""
import json, math, sys
from collections import defaultdict

AUTO_T, REVIEW_T = 0.70, 0.45
EXCLUDE = {'5018','5038','4116'}   # evidence suspects + confirmed frequent stranger

def unesc(s):
    return s.replace('\\\\','\x00').replace('\\n','\n').replace('\\t','\t').replace('\\r','\r').replace('\x00','\\')
def rows(path, n):
    out=[]
    for line in open(path):
        line=line.rstrip('\n')
        if not line: continue
        p=line.split('\t', n-1)
        if len(p)==n: out.append([unesc(x) for x in p])
    return out
def norm(v):
    s=math.sqrt(sum(x*x for x in v)) or 1.0
    return [x/s for x in v]
def cos(a,b): return sum(x*y for x,y in zip(a,b))

# ---------- references ----------
by=defaultdict(list)          # name -> [(sid, vec)]
for name, sid, emb in rows('/tmp/fm_named.tsv', 3):
    try: v=json.loads(emb)
    except Exception: continue
    if isinstance(v,list) and len(v)==512: by[name].append((sid, norm(v)))

def centroids(exclude):
    c={}
    for n,items in by.items():
        keep=[v for i,(sid,v) in enumerate(items) if (n,i) not in exclude]
        if not keep: continue
        s=[0.0]*512
        for v in keep:
            for j in range(512): s[j]+=v[j]
        c[n]=norm([x/len(keep) for x in s])
    return c

# ---------- margin audit (2 passes) ----------
quarantine=set()
for _ in range(2):
    cent=centroids(quarantine)
    newq=set()
    for n,items in by.items():
        keep=[(i,v) for i,(sid,v) in enumerate(items) if (n,i) not in quarantine]
        if len(keep)<3: continue
        s=[0.0]*512
        for _i,v in keep:
            for j in range(512): s[j]+=v[j]
        k=len(keep)
        for i,v in keep:
            own=norm([(s[j]-v[j])/(k-1) for j in range(512)])
            self_sim=cos(v,own)
            best_other=max((cos(v,c) for m,c in cent.items() if m!=n), default=-1)
            if best_other > self_sim: newq.add((n,i))
    quarantine=newq
cent=centroids(quarantine)

qc=defaultdict(int)
for n,i in quarantine: qc[n]+=1
total_named=sum(len(v) for v in by.values())
print(f"REFERENCE AUDIT: {len(quarantine)} of {total_named} named crops are closer to ANOTHER person than their own")
print(f"  people affected: {len(qc)} of {len(by)}")
for n,c in sorted(qc.items(), key=lambda x:-x[1])[:12]:
    print(f"    {n:32s} {c:3d} suspect / {len(by[n]):3d} crops  ({c/len(by[n])*100:.0f}%)")

# ---------- unknown clusters ----------
uc=defaultdict(list)
for sid, emb, ver in rows('/tmp/fm_unnamed.tsv', 3):
    try: v=json.loads(emb)
    except Exception: continue
    if not (isinstance(v,list) and len(v)==512): continue
    try: q=json.loads(ver) if ver and ver!='{}' else {}
    except Exception: q={}
    nf=q.get('non_face',0.0); ic=q.get('is_invalid_cropped',0.0)
    uc[sid].append((norm(v), max(0.05,(1.0-nf)*(1.0-0.5*ic))))

groups={}
for ext, gid, name, hits in rows('/tmp/fm_groups.tsv', 4):
    groups[ext]=(gid, name, int(hits or 0))

results=[]
for sid, items in uc.items():
    if sid in EXCLUDE: continue
    p=[0.0]*512; tw=0.0
    for v,w in items:
        for j in range(512): p[j]+=w*v[j]
        tw+=w
    p=norm([x/tw for x in p])
    scored=sorted(((n, cos(p,c)) for n,c in cent.items()), key=lambda x:-x[1])
    top, s1 = scored[0]
    s2 = scored[1][1] if len(scored)>1 else -1
    results.append({"sid":sid,"n":len(items),"top":top,"score":round(s1,4),
                    "margin":round(s1-s2,4),"second":scored[1][0] if len(scored)>1 else None,
                    "gid":groups.get(sid,(None,'',0))[0],"hits":groups.get(sid,(None,'',0))[2]})
results.sort(key=lambda r:-r["score"])
auto=[r for r in results if r["score"]>=AUTO_T]
review=[r for r in results if REVIEW_T<=r["score"]<AUTO_T]
print(f"\nCLUSTER SCAN: {len(results)} unnamed clusters scored (excluded {len(EXCLUDE)})")
print(f"  AUTO   >= {AUTO_T}: {len(auto)}")
print(f"  REVIEW >= {REVIEW_T}: {len(review)}")
print(f"  below  : {len(results)-len(auto)-len(review)}")
if auto:
    print("\n  --- would AUTO-APPLY ---")
    for r in auto:
        vis = "in UI" if r["gid"] else "INVISIBLE"
        print(f"    sid={r['sid']:6s} -> {r['top']:30s} {r['score']:.3f} (margin {r['margin']:+.3f}) {r['n']} crops, {vis}")
print("\n  --- top of review band (for the weekly page) ---")
for r in review[:10]:
    vis = "in UI" if r["gid"] else "INVISIBLE"
    print(f"    sid={r['sid']:6s} -> {r['top']:30s} {r['score']:.3f} (2nd: {r['second']}) {r['n']} crops, {vis}")
json.dump({"quarantine":[[n,i] for n,i in sorted(quarantine)],"results":results},
          open('/root/face-match/scan-result.json','w'))
print(f"\nwrote /root/face-match/scan-result.json")
