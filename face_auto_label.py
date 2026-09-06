#!/usr/bin/env python3
"""Periodic face auto-labeller (mm.pc). Two sources:
  1. Access badge correlation  (ground truth, high yield)
  2. Embedding matcher         (for faces badges can't reach)
Applies both, logs undo, Pushovers a summary."""
import asyncio, json, subprocess, sys, datetime, os, shlex
from collections import defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import access_protect_correlator as apc

GUEST = "unvr.pc"
LOG   = os.path.join(HERE, "face-auto-label.jsonl")
DRY   = "--apply" not in sys.argv
API   = "/proxy/protect/api/recognition/face/assign-group"

def guest(cmd, timeout=900):
    return subprocess.run(["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=20", GUEST, cmd],
                          capture_output=True, text=True, timeout=timeout)

def notify(msg, title, prio="0"):
    subprocess.run(["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=20", GUEST,
                    "sudo /usr/local/sbin/face-match-notify.sh %s %s %s"
                    % (shlex.quote(msg), shlex.quote(title), prio)],
                   capture_output=True, text=True, timeout=90)

def build_badge_job():
    r = guest("sudo python3 /root/face-match/badge_correlate.py")
    if r.returncode != 0:
        return None, "badge correlate failed: " + (r.stderr or r.stdout)[:200]
    raw = guest("sudo cat /root/face-match/badge-proposals.json").stdout
    d = json.loads(raw)
    nm = d.get("namemap", {})
    by = defaultdict(list)
    for p in d.get("proposals", []):
        if p["person"] in nm:
            by[(nm[p["person"]]["gid"], nm[p["person"]]["group_name"])].append(p["oid"])
    return [{"to_group": g, "person": n, "objectIds": o, "source": "badge"}
            for (g, n), o in by.items()], None

def build_embed_job():
    r = guest("sudo python3 /root/face-match/nightly_scan.py")
    if r.returncode != 0:
        return [], "embed scan failed"
    d = json.loads(guest("sudo cat /root/face-match/job.json").stdout)
    return [dict(j, source="embedding") for j in d.get("job", [])], None

async def main():
    started = datetime.datetime.now()
    badge, err1 = build_badge_job()
    if badge is None:
        notify(err1, "Face labeller error", "1"); print(err1); return
    embed, err2 = build_embed_job()
    job = badge + embed
    nb = sum(len(j["objectIds"]) for j in badge)
    ne = sum(len(j["objectIds"]) for j in embed)
    print("badge=%d faces in %d batches | embedding=%d" % (nb, len(badge), ne))
    if DRY:
        for j in job: print("  WOULD %-8s %-32s %2d" % (j["source"], j["person"], len(j["objectIds"])))
        return
    if not job:
        notify("Nothing new to label this run.", "Face labeller: quiet", "-1"); return

    c = apc._AdminClient()
    if not await c._ensure():
        notify("Could not authenticate to Protect.", "Face labeller error", "1"); return
    ok = fail = faces = 0
    per_person = {}   # person -> faces labelled this run, summed across badge + embedding batches
    with open(LOG, "a") as log:
        for j in job:
            r = await c.post(API, {"groupId": j["to_group"], "objectIds": j["objectIds"]})
            st = r[0] if r else None
            rec = dict(j); rec["http"] = st
            rec["ts"] = datetime.datetime.now().isoformat(timespec="seconds")
            log.write(json.dumps(rec) + "\n"); log.flush()
            if st in (200, 201):
                ok += 1; faces += len(j["objectIds"])
                per_person[j["person"]] = per_person.get(j["person"], 0) + len(j["objectIds"])
                print("  OK   %-8s %-32s %2d" % (j["source"], j["person"], len(j["objectIds"])))
            else:
                fail += 1; print("  FAIL %-8s %s http=%s" % (j["source"], j["person"], st))
    if c.session: await c.session.close()
    # One entry per person with the combined total. A person reached in both
    # the badge and the embedding pass used to be announced once per batch
    # ("Jane Doe (1), Jane Doe (1), ..."); now "Jane Doe (3)".
    lines = ["%s (%d)" % (person, n)
             for person, n in sorted(per_person.items(), key=lambda kv: (-kv[1], kv[0]))]
    msg = ", ".join(lines)
    if fail: msg += " -- %d batch(es) FAILED." % fail
    notify(msg, "Faces labelled: %d" % faces, "1" if fail else "0")
    print("applied %d batches, %d faces, %d failed" % (ok, faces, fail))

asyncio.run(main())
