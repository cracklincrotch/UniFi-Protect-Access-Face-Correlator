#!/bin/bash
# Hourly census of every face-related store. Append-only.
# Exists because face captures appeared to vanish on 2026-09-01 and there was no
# historical record to prove whether anything was actually being deleted. If a
# count ever DROPS, this log gives the timestamp and the delta instead of a hunch.
LOG=/data/face-census.log
exec 9>/var/lock/face-census.lock
flock 9
TS=$(date -Is)
q() { sudo -u postgres psql -p "$1" -d "$2" -t -A -c "$3" 2>/dev/null | tr -d '[:space:]'; }
{
  printf '%s' "$TS"
  printf ' face_objects=%s'   "$(q 5433 unifi-protect "SELECT count(*) FROM \"smartDetectObjects\" WHERE type='face';")"
  printf ' face_groups=%s'    "$(q 5433 unifi-protect "SELECT count(*) FROM \"smartDetectObjectGroups\" WHERE type='face';")"
  printf ' named_groups=%s'   "$(q 5433 unifi-protect "SELECT count(*) FROM \"smartDetectObjectGroups\" WHERE type='face' AND name IS NOT NULL AND name<>'';")"
  printf ' with_image=%s'     "$(q 5433 unifi-protect "SELECT count(*) FROM \"smartDetectObjectGroups\" WHERE type='face' AND image IS NOT NULL AND length(image)>0;")"
  printf ' detections=%s'     "$(q 5433 unifi-protect "SELECT COALESCE(sum(\"detectionsCount\"),0) FROM \"smartDetectObjectGroups\" WHERE type='face';")"
  printf ' oldest_face=%s'    "$(q 5433 unifi-protect "SELECT COALESCE(min(\"createdAt\")::date::text,'-') FROM \"smartDetectObjects\" WHERE type='face';")"
  printf ' ui_face_db=%s'     "$(q 5433 smart_detect_face "SELECT count(*) FROM ui_face_db;")"
  printf ' ui_named=%s'       "$(q 5433 smart_detect_face "SELECT count(*) FROM ui_face_db WHERE subject_name IS NOT NULL AND subject_name<>'';")"
  printf ' identity_data=%s'  "$(q 5433 smart_detect_face "SELECT count(*) FROM ui_face_identity_data;")"
  printf ' pseudo_merge=%s'   "$(q 5433 smart_detect_face "SELECT count(*) FROM ui_pseudo_merge;")"
  printf ' enrolled=%s'       "$(q 5432 unifi-user-assets "SELECT count(*) FROM user_asset_face WHERE deleted_at IS NULL;")"
  printf '\n'
} >> "$LOG"
# keep it bounded; one line an hour is ~9KB/year, but trim anyway
tail -n 20000 "$LOG" > "$LOG.tmp" && mv "$LOG.tmp" "$LOG"
