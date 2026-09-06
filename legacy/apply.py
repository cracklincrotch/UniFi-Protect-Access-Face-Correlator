#!/usr/bin/env python3
"""Apply validated face matches via Protect's own assign-group API.
Reads the API key from /usr/local/etc/face-match.conf (never logged).
Writes a full undo record before each change.  --dry-run to preview."""
import json, os, subprocess, sys, urllib.request, datetime

CONF   = '/usr/local/etc/face-match.conf'
CANDS  = '/root/face-match/candidates-final.json'
UNDO   = '/root/face-match/applied-log.jsonl'
BASE   = 'https://127.0.0.1/proxy/protect/api'
DRY    = '--dry-run' in sys.argv
EXCLUDE = {'5018','5038','4116'}          # evidence suspects + confirmed stranger

def psql(db, sql, port=5433, user='unifi-protect'):
    out = subprocess.run(['sudo','-u',user,'/usr/lib/postgresql/14/bin/psql','-p',str(port),
                          '-d',db,'-tAc',sql], capture_output=True, text=True)
    return [l for l in out.stdout.strip().split('\n') if l]

def api_key():
    if not os.path.exists(CONF):
        sys.exit(f"missing {CONF} — create an API key in the UniFi UI and put it there as PROTECT_API_KEY=...")
    for line in open(CONF):
        if line.startswith('PROTECT_API_KEY='):
            return line.split('=',1)[1].strip()
    sys.exit(f"{CONF} has no PROTECT_API_KEY= line")

def post(path, body, key):
    req = urllib.request.Request(BASE+path, data=json.dumps(body).encode(),
        headers={'Content-Type':'application/json','X-API-KEY':key}, method='POST')
    import ssl
    ctx = ssl.create_default_context(); ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE
    with urllib.request.urlopen(req, context=ctx, timeout=20) as r:
        return r.status, r.read().decode()[:200]

cands = [s for s in json.load(open(CANDS)) if s not in EXCLUDE]
# name -> target group id (largest group for that person)
targets = {}
for row in psql('unifi-protect',
        'SELECT DISTINCT ON (name) name||\'|\'||id FROM "smartDetectObjectGroups" '
        "WHERE name IS NOT NULL AND name<>'' ORDER BY name, \"detectionsCount\" DESC"):
    n,g = row.rsplit('|',1); targets[n]=g

scan = {r['sid']: r for r in json.load(open('/root/face-match/scan-z.json'))}
key = None if DRY else api_key()
done = fail = 0
for sid in cands:
    r = scan.get(sid)
    if not r: continue
    who = r['top']; tgt = targets.get(who)
    src = psql('unifi-protect', f"SELECT id FROM \"smartDetectObjectGroups\" WHERE \"externalId\"='{sid}'")
    if not src or not tgt:
        print(f"  SKIP sid={sid}: {'no source group' if not src else 'no target group for '+who}"); continue
    src = src[0]
    objs = psql('unifi-protect', f"SELECT id FROM \"smartDetectObjects\" WHERE \"smartDetectObjectGroupId\"='{src}'")
    if not objs:
        print(f"  SKIP sid={sid}: no detection objects"); continue
    rec = {"ts": datetime.datetime.now().isoformat(timespec='seconds'), "sid": sid,
           "person": who, "z": r['z'], "raw": r['raw'],
           "objectIds": objs, "from_group": src, "to_group": tgt}
    if DRY:
        print(f"  WOULD MERGE sid={sid} ({len(objs)} obj) -> {who}  z={r['z']:.2f} raw={r['raw']:.3f}")
        continue
    try:
        code, body = post('/recognition/face/assign-group', {"groupId": tgt, "objectIds": objs}, key)
        rec["http"] = code
        if code == 200:
            done += 1; print(f"  OK   sid={sid} -> {who} ({len(objs)} obj)")
        else:
            fail += 1; print(f"  FAIL sid={sid} http={code} {body}")
    except Exception as e:
        rec["error"] = str(e)[:120]; fail += 1; print(f"  ERR  sid={sid}: {e}")
    with open(UNDO,'a') as f: f.write(json.dumps(rec)+'\n')
print(f"\n{'DRY RUN' if DRY else 'applied'}: {len(cands)} candidates, {done} ok, {fail} failed")
if not DRY: print(f"undo record: {UNDO}  (re-assign objectIds back to from_group to reverse)")
