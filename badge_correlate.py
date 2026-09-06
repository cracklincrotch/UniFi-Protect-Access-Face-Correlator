#!/usr/bin/env python3
"""Correlate unnamed Protect face detections with Access badge events.
Rule: unique named badge within +/-3s, camera associated with that door,
and exactly ONE face detected in the window (no tailgating ambiguity).

Reads Protect and the Access event log through common.psql(); reads the
operator overrides from and writes badge-proposals.json to the state
directory (common.STATE). Runs wherever those are reachable."""
import bisect, json
from collections import defaultdict, Counter

from common import psql, STATE, PROTECT_DB, ACCESS_LOG_DB, PROTECT_DB_PORT, ACCESS_LOG_DB_PORT

WIN = 3000


def copy(port, db, sql):
    """Bulk read; RAISES on failure.

    This used to return `.stdout` and ignore both the return code and stderr.
    When the unifi-access 4.3.3 upgrade (2026-08-02) retired the separate
    access cluster, this silently returned "" -> badges=[] -> doormap={} ->
    zero proposals, and the labeller logged "badge=0" as though that were a
    normal quiet run. It did that for 29 days before anyone noticed."""
    return psql(port, db, sql, copy=True)


badges = []
for l in copy(ACCESS_LOG_DB_PORT, ACCESS_LOG_DB,
    "SELECT published, source->'actor'->>'display_name', COALESCE(source->'target'->0->>'display_name','?') "
    "FROM json_systemlog WHERE event_type='access.door.unlock' "
    "AND source->'actor'->>'display_name' IS NOT NULL AND source->'actor'->>'display_name' NOT IN ('N/A','') "
    "AND published > 0").split('\n'):
    p = l.split('\t')
    if len(p) == 3 and p[1]:
        try: badges.append((int(p[0]), p[1], p[2]))
        except Exception: pass
badges.sort(); BT = [b[0] for b in badges]

faces = []
for l in copy(PROTECT_DB_PORT, PROTECT_DB,
    'SELECT s."detectedAt", s.id, COALESCE(s."thumbnailId",\'\'), COALESCE(c.name,\'?\'), '
    'COALESCE(NULLIF(g.name,\'\'),\'\'), COALESCE(g.id,\'\'), COALESCE(g."externalId",\'\') '
    'FROM "smartDetectObjects" s LEFT JOIN cameras c ON c.id=s."cameraId" '
    'JOIN "smartDetectObjectGroups" g ON g.id=s."smartDetectObjectGroupId" '
    'WHERE s.type=\'face\' AND s."detectedAt" > 0').split('\n'):
    p = l.split('\t')
    if len(p) == 7:
        try: faces.append((int(p[0]), p[1], p[2], p[3], p[4], p[5], p[6]))
        except Exception: pass
faces.sort(); FT = [f[0] for f in faces]

# (camera, time-bucket) -> how many faces were in that shot. 500ms buckets: two
# faces in one frame can land a few ms apart when scored separately.
# Access READER cameras -- the UA G3 Intercom / UA G3 Pro devices. The person
# standing at a reader IS the person badging; that camera sees them by
# definition. Every other camera is inference: an exterior sees them arriving
# (usually), an interior sees people who were ALREADY INSIDE and cannot contain
# the badge holder yet. Measured leave-one-out against 250 curated faces:
#     READER   219 right /  5 wrong   97.8%
#     EXTERIOR  33 right /  4 wrong   89.2%
#     INTERIOR   2 right /  1 wrong   66.7%
# So proposals are restricted to reader frames.
_ct = psql(PROTECT_DB_PORT, PROTECT_DB,
           "SELECT name||'|'||COALESCE(type,'') FROM cameras WHERE name IS NOT NULL")
READER_CAMS = {l.rsplit('|', 1)[0] for l in _ct.strip().split('\n')
               if '|' in l and l.rsplit('|', 1)[1].startswith('UA ')}
if not READER_CAMS:
    raise RuntimeError("no UA reader cameras found -- refusing to run blind")

# INTERIOR cameras are excluded from proposals. At badge time the person who
# badged is standing AT THE DOOR; an unnamed face on a camera inside the
# building is someone who was ALREADY IN, so eliminating down to them and
# calling them the badge holder is a guess. Measured leave-one-out it scores
# 2 right / 1 wrong. Readers and exterior cameras both see the person arriving
# and are kept: 252 right / 9 wrong = 96.6%, which trades 4 extra errors for 33
# extra correct labels -- correcting four is less work than curating thirty-three.
_INTERIOR_MARKS = (' if1', ' if2', ' if3', ' ir1', ' ir2', ' ir3',
                   'interior', 'int ', 'hall', 'laundry')
def _is_interior(cam):
    c = ' ' + (cam or '').lower()
    return any(m in c for m in _INTERIOR_MARKS)

SHOT_MS = 500
shots = Counter((f[3], f[0] // SHOT_MS) for f in faces)

# Learn door -> camera association from co-occurrence, +/-3s.
#
# A FORWARD 0..20s window with a tightness test was tried on 2026-08-31: it
# produced a richer, entirely correct-looking map (24 pairings vs 11, including
# the interior cameras) but MEASURED WORSE -- back-tested against 250
# hand-curated faces it scored 93.8% against 96.1% for this narrow form, adding
# 5 errors and no extra correct labels. The reason is that an interior camera
# sees the person 6-10s after the badge with a p90 near 21s, and in that spread
# a second person has often badged in on their own credential. Per-camera delay
# OFFSETTING was tried too and did not rescue it (92.3 / 93.3 / 94.1%).
# Interior cameras need direction (derivable from smartDetectTracks.payload
# coords), not a wider window. Until that exists, stay narrow.
assoc = defaultdict(Counter)
for t, oid, th, cam, nm, gid, ext in faces:
    lo = bisect.bisect_left(BT, t-3000); hi = bisect.bisect_right(BT, t+3000)
    for i in range(lo, hi): assoc[badges[i][2]][cam] += 1
doormap = defaultdict(set)
for d, cc in assoc.items():
    thr = max(2, 0.15*sum(cc.values()))
    doormap[d] = {c for c, k in cc.items() if k >= thr}

# Manual pairings, unioned on top. Keys beginning with "_" are ignored, which
# is how the interior-camera pairings are parked: documented, not active.
VICINITY = STATE / 'vicinity_cameras.json'
try:
    for _door, _cams in json.load(open(VICINITY)).items():
        if _door.startswith('_'):
            continue
        doormap[_door].update(_cams)
except FileNotFoundError:
    pass
except Exception as _e:
    print("  WARNING: could not read %s: %s" % (VICINITY, _e))
doormap = dict(doormap)

# Cameras eligible to carry a proposal: everything in the doormap that is not
# interior. Printed so the classification is auditable rather than implicit.
ALLOWED_CAMS = {c for cams in doormap.values() for c in cams if not _is_interior(c)}
_excluded = {c for cams in doormap.values() for c in cams if _is_interior(c)}
if _excluded:
    print("  interior cameras excluded from proposals: " + ", ".join(sorted(_excluded)))

# Name matching is needed by BOTH the proposal guard below and the namemap at
# the end, so it is defined here rather than after the loop.
def _norm(x):
    return set(''.join(c for c in x.lower() if c.isalnum() or c == ' ').split())

overrides = {}
try:
    overrides = json.load(open(STATE / 'namemap-overrides.json'))
except Exception:
    pass

def _same_person(badge, group):
    """Does this badge name refer to the same person as this Protect group?"""
    if badge in overrides:
        return overrides[badge].get('group_name') == group
    return len(_norm(badge) & _norm(group)) >= 2


rejected = set()
try:
    rejected = set(json.load(open(STATE / 'rejected.json')))
except Exception:
    pass

proposals = []
for t, oid, th, cam, nm, gid, ext in faces:
    if nm or oid in rejected: continue                                   # already named
    lo = bisect.bisect_left(BT, t-WIN); hi = bisect.bisect_right(BT, t+WIN)
    hits = [(badges[i][1], badges[i][2], badges[i][0]) for i in range(lo, hi)
            if cam in doormap.get(badges[i][2], set())]
    if len({h[0] for h in hits}) != 1: continue
    person, door, bt = hits[0]
    # Readers and exterior cameras only -- interior is excluded, see above.
    if cam not in ALLOWED_CAMS:
        continue

    # Elimination, scoped to THIS CAMERA. Scoping matters: guard B looked across
    # every camera at the door, so a person recognised out in the yard blocked
    # the entry camera two seconds later (this is why one tenant went
    # unlabelled on 2026-08-31). What happens in the yard says nothing about who
    # is standing at the reader.
    #   - 2+ unidentified faces on this camera -> cannot tell which is which.
    #   - the badge holder ALREADY recognised on this camera -> they are
    #     accounted for, so this face is somebody else.
    _lo = bisect.bisect_left(FT, t - WIN); _hi = bisect.bisect_right(FT, t + WIN)
    _here = [f for f in faces[_lo:_hi] if f[3] == cam and f[1] != oid]
    if 1 + sum(1 for f in _here if not f[4]) > 1:
        continue
    if any(f[4] and _same_person(person, f[4]) for f in _here):
        continue

    if shots[(cam, t // SHOT_MS)] != 1: continue      # 2+ people in frame -> ambiguous
    proposals.append({"oid": oid, "thumb": th, "cam": cam, "ts": t,
                      "person": person, "door": door, "delta": (t-bt)/1000.0,
                      "group": gid, "ext": ext})

# --- badge name -> Protect group (2 name parts must match; overrides file wins) ---
grows = psql(PROTECT_DB_PORT, PROTECT_DB,
    'SELECT DISTINCT ON (name) name||\'|\'||id||\'|\'||"detectionsCount" FROM "smartDetectObjectGroups" '
    "WHERE name IS NOT NULL AND name<>'' ORDER BY name, \"detectionsCount\" DESC").strip().split('\n')
groups = [r.rsplit('|', 2) for r in grows if r]
namemap = {}
for b in sorted({p['person'] for p in proposals}):
    if b in overrides:
        namemap[b] = overrides[b]; continue
    bt = _norm(b); best = None; score = 0
    for gname, gid, hits in groups:
        sc = len(bt & _norm(gname))
        if sc > score: score, best = sc, (gname, gid, int(hits))
    if best and score >= 2:
        namemap[b] = {"group_name": best[0], "gid": best[1], "hits": best[2], "score": score}
unmapped = sorted({p['person'] for p in proposals} - set(namemap))
if unmapped: print("  UNMAPPED badge names (skipped):", ", ".join(unmapped))

json.dump({"doormap": {k: sorted(v) for k, v in doormap.items()},
           "namemap": namemap, "proposals": proposals},
          open(STATE / 'badge-proposals.json', 'w'), indent=1)
c = Counter(p["person"] for p in proposals)
print("proposals=%d  distinct people=%d" % (len(proposals), len(c)))
for n, k in c.most_common(12):
    print("  %-26s %3d" % (n, k))
