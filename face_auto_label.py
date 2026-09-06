#!/usr/bin/env python3
"""Periodic face auto-labeller. Two sources:
  1. Access badge correlation  (ground truth, high yield)   -> badge_correlate.py
  2. Embedding matcher         (for faces badges can't reach) -> nightly_scan.py
Runs both as local steps, applies the result to Protect through an admin
session (common.ProtectSession, standard library only), appends an undo
record per batch, and sends one Pushover summary (one line per person with
the combined total).

Without --apply it is a dry run. Where it runs is configuration (see
common.py): the analysis steps need the NVR's database, the apply step needs
the Protect API, the summary needs Pushover credentials."""
import json, subprocess, sys, datetime
from collections import defaultdict
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import common          # standard library only: this job must run on stock UniFi OS

LOG = common.STATE / "face-auto-label.jsonl"
DRY = "--apply" not in sys.argv
API = "/proxy/protect/api/recognition/face/assign-group"


def step(script, timeout=900):
    """Run one analysis script with this interpreter, in this directory."""
    try:
        return subprocess.run([sys.executable, str(HERE / script)], cwd=str(HERE),
                              capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess([script], 124, "", "%s exceeded %d s" % (script, timeout))


def build_badge_job():
    r = step("badge_correlate.py")
    if r.returncode != 0:
        return None, "badge correlate failed: " + (r.stderr or r.stdout)[-300:]
    d = json.load(open(common.STATE / "badge-proposals.json"))
    nm = d.get("namemap", {})
    by = defaultdict(list)
    for p in d.get("proposals", []):
        if p["person"] in nm:
            by[(nm[p["person"]]["gid"], nm[p["person"]]["group_name"])].append(p["oid"])
    return [{"to_group": g, "person": n, "objectIds": o, "source": "badge"}
            for (g, n), o in by.items()], None


def build_embed_job():
    r = step("nightly_scan.py")
    if r.returncode != 0:
        return [], "embed scan failed: " + (r.stderr or r.stdout)[-300:]
    d = json.load(open(common.STATE / "job.json"))
    return [dict(j, source="embedding") for j in d.get("job", [])], None


def main():
    badge, err1 = build_badge_job()
    if badge is None:
        common.notify(err1, "Face labeller error", "1"); print(err1); return
    embed, err2 = build_embed_job()
    if err2:
        print(err2)
    job = badge + embed
    nb = sum(len(j["objectIds"]) for j in badge)
    ne = sum(len(j["objectIds"]) for j in embed)
    print("badge=%d faces in %d batches | embedding=%d" % (nb, len(badge), ne))
    if DRY:
        for j in job: print("  WOULD %-8s %-32s %2d" % (j["source"], j["person"], len(j["objectIds"])))
        return
    if not job:
        common.notify("Nothing new to label this run." + (" (%s)" % err2 if err2 else ""),
                      "Face labeller: quiet", "-1"); return

    c = common.ProtectSession()
    if not c.login():
        common.notify("Could not authenticate to Protect.", "Face labeller error", "1"); return
    ok = fail = faces = 0
    per_person = {}   # person -> faces labelled this run, summed across badge + embedding batches
    with open(LOG, "a") as log:
        for j in job:
            r = c.post(API, {"groupId": j["to_group"], "objectIds": j["objectIds"]})
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
    # One entry per person with the combined total. A person reached in both
    # the badge and the embedding pass used to be announced once per batch
    # ("Jane Doe (1), Jane Doe (1), ..."); now "Jane Doe (3)".
    lines = ["%s (%d)" % (person, n)
             for person, n in sorted(per_person.items(), key=lambda kv: (-kv[1], kv[0]))]
    msg = ", ".join(lines)
    if fail: msg += " -- %d batch(es) FAILED." % fail
    if err2: msg += " -- " + err2
    common.notify(msg, "Faces labelled: %d" % faces, "1" if fail else "0")
    print("applied %d batches, %d faces, %d failed" % (ok, faces, fail))

main()
