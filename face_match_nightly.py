#!/usr/bin/env python3
"""Nightly face matcher (runs on mm.pc).
Scan on the guest -> apply via Protect's private API -> Pushover summary.
Credentials come from the correlator module; nothing is stored here."""
import asyncio, json, subprocess, sys, datetime, os, shlex

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import access_protect_correlator as apc

GUEST = "unvr.pc"
LOG   = os.path.join(HERE, "face-match-applied.jsonl")
DRY   = "--apply" not in sys.argv

def guest(cmd, timeout=600):
    return subprocess.run(["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=20", GUEST, cmd],
                          capture_output=True, text=True, timeout=timeout)

def notify(msg, title="Face matcher", prio="0"):
    subprocess.run(["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=20", GUEST,
                    "sudo /usr/local/sbin/face-match-notify.sh %s %s %s"
                    % (shlex.quote(msg), shlex.quote(title), prio)],
                   capture_output=True, text=True, timeout=90)

async def main():
    started = datetime.datetime.now()
    r = guest("sudo python3 /root/face-match/nightly_scan.py")
    if r.returncode != 0:
        notify("Nightly scan FAILED on the guest:\n%s" % (r.stderr or r.stdout)[:300],
               "Face matcher error", "1")
        print("scan failed:", r.stderr[:300]); return
    summary = (r.stdout or "").strip()
    raw = guest("sudo cat /root/face-match/job.json").stdout
    try:
        data = json.loads(raw)
    except Exception as e:
        notify("Nightly scan produced unreadable job.json (%s)" % e, "Face matcher error", "1")
        return
    job = data.get("job", [])
    print("%s | actionable=%d" % (summary, len(job)))
    if DRY:
        for j in job:
            print("  WOULD %-6s -> %-30s z=%.2f raw=%.3f" % (j["sid"], j["person"], j["z"], j["raw"]))
        return
    if not job:
        notify("Nightly scan: %s\nNothing met the auto-merge bar." % summary,
               "Face matcher: no changes", "-1")
        return

    c = apc._AdminClient()
    if not await c._ensure():
        notify("Nightly matcher could not authenticate to Protect.", "Face matcher error", "1")
        return
    ok, fail, lines = 0, 0, []
    with open(LOG, "a") as log:
        for j in job:
            res = await c.post("/proxy/protect/api/recognition/face/assign-group",
                               {"groupId": j["to_group"], "objectIds": j["objectIds"]})
            status = res[0] if res else None
            rec = dict(j); rec["http"] = status
            rec["ts"] = datetime.datetime.now().isoformat(timespec="seconds")
            log.write(json.dumps(rec) + "\n")
            if status in (200, 201):
                ok += 1; lines.append("%s (%d face%s)" % (j["person"], len(j["objectIds"]),
                                                          "" if len(j["objectIds"]) == 1 else "s"))
                print("  OK   %-6s -> %s" % (j["sid"], j["person"]))
            else:
                fail += 1; print("  FAIL %-6s http=%s" % (j["sid"], status))
    if c.session: await c.session.close()

    took = (datetime.datetime.now() - started).seconds
    msg = "Merged %d face%s into:\n%s\n\n%s\nRun took %ds." % (
        ok, "" if ok == 1 else "s", "\n".join("  * " + l for l in lines), summary, took)
    if fail: msg += "\n%d FAILED - check the log." % fail
    notify(msg, "Face matcher: %d merged" % ok, "1" if fail else "0")
    print("applied %d, failed %d" % (ok, fail))

asyncio.run(main())
