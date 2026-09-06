#!/usr/bin/env python3
"""Embedding face-match scan. Scores unnamed clusters against named
references and emits job.json (in common.STATE) for the applier. Read-only
against Protect; talks to the database through common.psql()."""
import json, math, random, sys
from collections import defaultdict

from common import psql, STATE, PROTECT_DB, FACE_DB, PROTECT_DB_PORT

Z_MIN, MARGIN_MIN, REFS_MIN, RAW_MIN = 4.0, 2.0, 15, 0.38
EXCLUDE = {'5018', '5038', '4116'}          # evidence suspects + confirmed stranger


def q(db, sql):
    """Small query -> list of non-empty lines. Raises on failure (the old
    version returned [] on any error, which is indistinguishable from
    'nothing to do')."""
    return [l for l in psql(PROTECT_DB_PORT, db, sql).split('\n') if l]


def copy(db, sql):
    return psql(PROTECT_DB_PORT, db, sql, copy=True)


def unesc(s):
    return s.replace('\\\\', '\x00').replace('\\n', '\n').replace('\\t', '\t').replace('\x00', '\\')

def norm(v):
    s = math.sqrt(sum(x * x for x in v)) or 1.0
    return [x / s for x in v]

def cos(a, b):
    return sum(x * y for x, y in zip(a, b))

# ---- references ----
by = defaultdict(list)
for line in copy(FACE_DB,
        "SELECT subject_name, embed::text FROM ui_face_db "
        "WHERE subject_name IS NOT NULL AND subject_name<>'' AND is_valid_embed").split('\n'):
    p = line.split('\t', 1)
    if len(p) != 2: continue
    try: v = json.loads(p[1])
    except Exception: continue
    if isinstance(v, list) and len(v) == 512: by[unesc(p[0])].append(norm(v))
if not by: sys.exit("no reference crops")
cent = {n: norm([sum(x[j] for x in vs) / len(vs) for j in range(512)]) for n, vs in by.items()}
nref = {n: len(vs) for n, vs in by.items()}

# ---- unnamed clusters (quality-weighted pooling) ----
uc = defaultdict(list)
for line in copy(FACE_DB,
        "SELECT subject_id, embed::text, COALESCE(verifier_score::text,'{}') FROM ui_face_db "
        "WHERE (subject_name IS NULL OR subject_name='') AND is_valid_embed").split('\n'):
    p = line.split('\t', 2)
    if len(p) != 3: continue
    try: v = json.loads(p[1])
    except Exception: continue
    if not (isinstance(v, list) and len(v) == 512): continue
    try: qs = json.loads(unesc(p[2])) if p[2] not in ('', '{}') else {}
    except Exception: qs = {}
    nf, ic = qs.get('non_face', 0.0), qs.get('is_invalid_cropped', 0.0)
    uc[p[0]].append((norm(v), max(0.05, (1.0 - nf) * (1.0 - 0.5 * ic))))

pooled = {}
for sid, items in uc.items():
    s = [0.0] * 512; tw = 0.0
    for v, w in items:
        for j in range(512): s[j] += w * v[j]
        tw += w
    pooled[sid] = norm([x / tw for x in s])

# ---- per-identity background stats (hub defence) ----
bg = random.Random(11).sample(list(pooled.values()), min(300, len(pooled))) if pooled else []
stats = {}
for n, c in cent.items():
    sims = [cos(c, b) for b in bg] or [0.0]
    mu = sum(sims) / len(sims)
    sd = math.sqrt(sum((x - mu) ** 2 for x in sims) / len(sims)) or 1e-6
    stats[n] = (mu, sd)

# ---- score + gate ----
cands = []
for sid, p in pooled.items():
    if sid in EXCLUDE: continue
    sc = sorted(((n, cos(p, c), (cos(p, c) - stats[n][0]) / stats[n][1]) for n, c in cent.items()),
                key=lambda x: -x[2])
    n1, raw1, z1 = sc[0]
    z2 = sc[1][2] if len(sc) > 1 else -9
    if z1 >= Z_MIN and (z1 - z2) >= MARGIN_MIN and nref[n1] >= REFS_MIN and raw1 >= RAW_MIN:
        cands.append({"sid": sid, "person": n1, "z": round(z1, 2),
                      "margin": round(z1 - z2, 2), "raw": round(raw1, 3), "crops": len(uc[sid])})

# ---- resolve groups + objects ----
targets = {}
for row in q(PROTECT_DB,
             'SELECT DISTINCT ON (name) name||\'|\'||id FROM "smartDetectObjectGroups" '
             "WHERE name IS NOT NULL AND name<>'' ORDER BY name, \"detectionsCount\" DESC"):
    n, g = row.rsplit('|', 1); targets[n] = g

job = []
for c in cands:
    tgt = targets.get(c["person"])
    src = q(PROTECT_DB,
            "SELECT id FROM \"smartDetectObjectGroups\" WHERE \"externalId\"='%s'" % c["sid"])
    if not tgt or not src: continue
    objs = q(PROTECT_DB,
             "SELECT id FROM \"smartDetectObjects\" WHERE \"smartDetectObjectGroupId\"='%s'" % src[0])
    if not objs: continue
    job.append(dict(c, from_group=src[0], to_group=tgt, objectIds=objs))

json.dump({"scanned": len(pooled), "candidates": len(cands), "job": job},
          open(STATE / 'job.json', 'w'), indent=1)
print("scanned=%d candidates=%d actionable=%d" % (len(pooled), len(cands), len(job)))
