#!/bin/bash
# Register the face auto-labeller timer on the NVR. Idempotent.
#
# Run it once after unpacking the tree under /data, and AGAIN AFTER EVERY
# FIRMWARE / UNIFI OS UPDATE: an update replaces the root filesystem, which
# takes /etc/systemd/system with it. /data survives, so the code, the state and
# secrets.env under /data/face-correlator do not need touching.
set -euo pipefail
DIR=${1:-/data/face-correlator}
[ -f "$DIR/face_auto_label.py" ] || { echo "no face_auto_label.py under $DIR" >&2; exit 1; }
[ -f "$DIR/secrets.env" ] || echo "warning: $DIR/secrets.env missing -- the job will not be able to log in" >&2
for u in face-auto-label.service face-auto-label.timer; do
    sed "s|/data/face-correlator|$DIR|g" "$DIR/ops/$u" > "/etc/systemd/system/$u"
done
chmod 700 "$DIR/state" 2>/dev/null || true
systemctl daemon-reload
systemctl enable --now face-auto-label.timer >/dev/null
echo "face-auto-label.timer: $(systemctl is-active face-auto-label.timer); next run $(systemctl list-timers face-auto-label.timer --no-legend | awk '{print $1, $2, $3}')"
