#!/usr/bin/env python3
"""
access_protect_correlator.py
─────────────────────────────────────────────────────────────────────────────
Correlates UniFi Access door-entry events with UniFi Protect face-detection
events to establish ground-truth person identity in Protect.

How it works
────────────
Two persistent WebSocket connections run concurrently:

  1. UniFi Access  wss://unvr.pc/proxy/access/api/v2/ws/notification
     Fires  access.logs.add  when a recognized person opens a door.

  2. UniFi Protect wss://unvr.pc/proxy/protect/integration/v1/subscribe/events
     Fires smartDetectZone events (type=face) as cameras detect faces.

When Access grants entry, the script waits FACE_SEARCH_POST_SEC seconds
(to give Protect time to complete its detection), then searches the in-memory
face-event buffer for detections within the correlation window
[ entry_time − FACE_SEARCH_PRE_SEC  …  entry_time + FACE_SEARCH_POST_SEC ].

Each matched pair is written to OUTPUT_DIR:
  • YYYYMMDD_HHMMSS_Name.json         — full correlation record
  • YYYYMMDD_HHMMSS_Name_face_NN.jpg  — Protect face-detection thumbnail
  • YYYYMMDD_HHMMSS_Name.access_avatar.jpg — Access profile photo (if set)

Setup
─────
No webhook configuration is required.  Just run the script:
    python3 access_protect_correlator.py

Optional: populate DOOR_CAMERA_MAP to restrict face-event matching to the
camera physically nearest each Access door.  Camera IDs are logged at startup.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import sys
import ssl
import time
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

import argparse
import aiohttp

# ── Configuration ─────────────────────────────────────────────────────────────
#
# Credentials are NOT in this file (it is public). They come from secrets.env
# next to it (mode 600, gitignored; see secrets.env.example) or from the
# environment, which takes precedence: PROTECT_HOST, PROTECT_API_KEY (the
# integration key -- reads only) and PROTECT_USER / PROTECT_PASS (an admin account
# with write scope: the private recognition API and the assign-group WRITE
# used by --teach-write need a logged-in session, not the key).
import common  # loads correlator.env + secrets.env into the environment; real env vars win

UNVR_HOST  = os.environ.get("PROTECT_HOST", "unvr.pc")
API_KEY    = os.environ.get("PROTECT_API_KEY", "")
ADMIN_USER = os.environ.get("PROTECT_USER", "")
ADMIN_PASS = os.environ.get("PROTECT_PASS", "")
if not API_KEY:
    sys.stderr.write("access_protect_correlator: PROTECT_API_KEY is not set "
                     "(see secrets.env.example)\n")

# Seconds BEFORE the Access entry timestamp to include Protect face events.
# People often stand at a door for several seconds before presenting a
# credential; 60 s covers the typical approach-to-badge interval.
FACE_SEARCH_PRE_SEC = 60

# Seconds AFTER the Access entry timestamp to (a) wait before searching, and
# (b) include in the search window.  Most cameras detect within a few seconds
# of the door opening; 30 s is a comfortable safety margin.
FACE_SEARCH_POST_SEC = 30

# Keep Protect face events in the ring buffer for this long.
FACE_BUFFER_TTL_SEC = 300   # 5 minutes

# Optional: map Access door aliases to Protect camera IDs to restrict
# correlations to the camera nearest each door.  Leave empty to accept
# face events from any camera.
# Camera IDs are printed at startup under "=== Protect cameras ===".
DOOR_CAMERA_MAP: Dict[str, str] = {
    # "110 Front Door": "69c2a20401495f03e40004be",
}

# Directory where correlation records and images are written.
OUTPUT_DIR = common.STATE / "correlations"

# Set to True via --dry-run; controls whether Protect is contacted at all.
DRY_RUN: bool = False

# ── Face-teaching (write-back) configuration ──────────────────────────────────
# THE ORIGINAL PURPOSE OF THIS SCRIPT: when Access deterministically identifies a
# person at a door (face credential → AUTHENTICATED, not guessed), push that
# Access-confirmed identity onto the Protect face for the same moment, so
# Protect's best-effort recognition learns.  ACCESS PREVAILS over Protect.
#
# Hard facts confirmed live (2026-05-31, 10.1.15.235, Protect 7.x):
#   • Recognition is a PRIVATE-API + ADMIN-SESSION feature (the X-API-KEY used for
#     the integration WS/REST does NOT reach /proxy/protect/api/...).
#   • Recognised identity is present ONLY on the LIST events endpoint
#     GET /proxy/protect/api/events?start=&end=&types=smartDetectZone — it enriches
#     each metadata.detectedThumbnails[type=face] with {name, group{id,name,
#     matchedName,confidence}}.  The single-event GET /events/{id} and the private
#     WS deltas return RAW thumbnails (group=None).  → read identity from the LIST.
#   • The reassignable unit is a "detection" record under a face group:
#     GET /proxy/protect/api/recognition/face/groups/{gid}/detections.
#     A thumbnail's croppedId == a detection's thumbnailId (the join key).
#   • Face groups (known people): GET /proxy/protect/api/recognition/face/groups
#     names are "<unit> <First Last>" e.g. "110-1 Jane Doe".
#
# TEACH_ENABLED (--teach) turns on the decision logic in DRY-RUN: it logs exactly
# which detection it WOULD reassign, to which person, and why — NO write.
# TEACH_WRITE (--teach-write, implies --teach) actually performs the assign-group
# POST.  Two-stage on purpose: observe first, then enable writes.
TEACH_ENABLED: bool = False
TEACH_WRITE:   bool = False

# Admin session for the PRIVATE recognition API.  May be a DIFFERENT host than
# UNVR_HOST if the recognition console differs from the integration-WS console
# (confirm this — if the two consoles don't share event ids, teaching must run
# against whichever box holds the faces).
PRIVATE_HOST: str = os.environ.get("PROTECT_PRIVATE_HOST", UNVR_HOST)
PRIVATE_USER: str = os.environ.get("PROTECT_USER", ADMIN_USER)
PRIVATE_PASS: str = os.environ.get("PROTECT_PASS", ADMIN_PASS)

# The reassign/assign WRITE endpoint, CONFIRMED 2026-05-31 via a mitmproxy capture
# of the Protect Faces UI:
#     POST /proxy/protect/api/recognition/face/assign-group
#     {"objectIds": ["<detection id>", ...], "groupId": "<target group id>"}
# One endpoint does both assign (unrecognised face) and reassign (wrong group) —
# it just sets the group for the given detection object ids.  Auth = admin session
# (X-CSRF-Token + TOKEN cookie), which _AdminClient already holds.
WRITE_ENDPOINT_CONFIRMED: bool = True

# ── Derived constants ─────────────────────────────────────────────────────────

_PROTECT_BASE = f"https://{UNVR_HOST}/proxy/protect/integration/v1"
_PROTECT_WS   = f"wss://{UNVR_HOST}/proxy/protect/integration/v1/subscribe/events"
_ACCESS_BASE  = f"https://{UNVR_HOST}/proxy/access/api/v2"
_ACCESS_WS    = f"wss://{UNVR_HOST}/proxy/access/api/v2/ws/notification"
_HEADERS      = {"X-API-KEY": API_KEY, "Accept": "application/json"}

# ── Logging ───────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger(__name__)

# ── SSL: accept self-signed UNVR certificate ──────────────────────────────────

_ssl = ssl.create_default_context()
_ssl.check_hostname = False
_ssl.verify_mode    = ssl.CERT_NONE

# ── Data structures ───────────────────────────────────────────────────────────

@dataclass
class FaceEvent:
    event_id           : str
    camera_id          : str
    start_ms           : int
    end_ms             : Optional[int]
    smart_detect_types : List[str]


@dataclass
class AccessEntry:
    person_name  : str          # normalized name for Protect matching
    raw_name     : str          # original full_name from Access
    person_id    : str
    door_name    : str
    timestamp_ms : int
    reader_camera_id : str = ""  # Protect camera id of the reader (activities_resource.alternate_id)


# ── Protect face-event buffer ─────────────────────────────────────────────────

class FaceEventBuffer:
    """
    Rolling in-memory store for Protect face-detection events.

    Protect sends 'add' when an event starts and 'update' messages as it
    progresses (e.g., to add the end timestamp).  The buffer keeps both
    indexed by event_id so updates are applied in-place.
    """

    def __init__(self, ttl_sec: int = FACE_BUFFER_TTL_SEC) -> None:
        self._by_id  : Dict[str, FaceEvent] = {}
        self._order  : deque[str]           = deque()   # insertion-ordered IDs
        self._ttl_ms : int                  = ttl_sec * 1000

    def upsert(self, event: FaceEvent) -> None:
        if event.event_id in self._by_id:
            # Apply update fields from the newer message.
            existing = self._by_id[event.event_id]
            if event.end_ms is not None:
                existing.end_ms = event.end_ms
            existing.smart_detect_types = event.smart_detect_types
        else:
            self._by_id[event.event_id] = event
            self._order.append(event.event_id)
        self._prune()

    def _prune(self) -> None:
        cutoff = int(time.time() * 1000) - self._ttl_ms
        while self._order:
            oldest_id = self._order[0]
            if self._by_id.get(oldest_id, FaceEvent("", "", 0, None, [])).start_ms < cutoff:
                self._order.popleft()
                self._by_id.pop(oldest_id, None)
            else:
                break

    def find_matches(
        self,
        entry   : AccessEntry,
        pre_ms  : int,
        post_ms : int,
    ) -> List[FaceEvent]:
        self._prune()
        window_start  = entry.timestamp_ms - pre_ms
        window_end    = entry.timestamp_ms + post_ms
        camera_filter = DOOR_CAMERA_MAP.get(entry.door_name)

        return [
            e for e in self._by_id.values()
            if window_start <= e.start_ms <= window_end
            and "face" in e.smart_detect_types
            and (camera_filter is None or e.camera_id == camera_filter)
        ]


_face_buffer = FaceEventBuffer()

# Maps Access device unique_id → human-readable alias.
# Populated by _log_access_doors() at startup; used in _parse_access_entry()
# to convert hardware device names (e.g. "UA-HUB-DOOR-EC91") to aliases.
_access_device_map: Dict[str, str] = {}

# Maps Protect camera id → camera name.
# Populated by _log_cameras() at startup; used to show names in logs/records.
_protect_camera_map: Dict[str, str] = {}


# ── Protect WebSocket subscriber ──────────────────────────────────────────────

def _handle_protect_message(raw: str) -> None:
    """
    Parse a Protect WebSocket text frame and add any face-detection event
    to the buffer.

    Observed format:
        {"type": "add"|"update",
         "item": {"id": "…", "modelKey": "event",
                  "type": "smartDetectZone",
                  "start": 1775094488679,
                  "end": 1775094497118,          ← absent until event closes
                  "device": "69c2a204…",
                  "smartDetectTypes": ["vehicle"]}}
    """
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return

    item = data.get("item", {})
    if item.get("modelKey") != "event":
        return

    if item.get("type") != "smartDetectZone":
        return

    smart_types = item.get("smartDetectTypes", [])
    if "face" not in smart_types:
        return

    fe = FaceEvent(
        event_id           = item["id"],
        camera_id          = item.get("device", ""),
        start_ms           = item.get("start", 0),
        end_ms             = item.get("end"),       # None until event closes
        smart_detect_types = smart_types,
    )
    _face_buffer.upsert(fe)

    action   = data.get("type", "")
    ts       = datetime.fromtimestamp(fe.start_ms / 1000).strftime("%H:%M:%S.%f")[:-3]
#    cam_name = _protect_camera_map.get(fe.camera_id, fe.camera_id[:8] + "…")
    cam_name = _protect_camera_map.get(fe.camera_id, fe.camera_id + "…")
    log.info(
        f"[PROTECT] Face event {action:6s} — "
#        f"id={fe.event_id[:8]}…  camera={cam_name!r}  "
        f"id={fe.event_id}  camera={cam_name!r}  "
        f"time={ts}  types={smart_types}"
    )


async def protect_subscriber(session: aiohttp.ClientSession) -> None:
    """Connect to Protect's event WebSocket; reconnect automatically."""
    while True:
        try:
            log.info("Connecting to Protect event WebSocket…")
            async with session.ws_connect(
                _PROTECT_WS,
                headers   = _HEADERS,
                ssl       = _ssl,
                heartbeat = 30,
            ) as ws:
                log.info("Protect WebSocket connected.")
                async for msg in ws:
                    if msg.type == aiohttp.WSMsgType.TEXT:
                        _handle_protect_message(msg.data)
                    elif msg.type in (
                        aiohttp.WSMsgType.ERROR,
                        aiohttp.WSMsgType.CLOSED,
                    ):
                        log.warning(f"Protect WS closed: {ws.exception()}")
                        break
        except Exception as exc:
            log.error(f"Protect WS error: {exc}")
        log.info("Protect WS: reconnecting in 10 s…")
        await asyncio.sleep(10)


# ── Name normalization ────────────────────────────────────────────────────────

def _normalize_access_name(full_name: str) -> str:
    """
    Normalize an Access full_name to match the name style used in Protect.

    Access first names may carry a descriptive prefix separated by a space,
    e.g. "Baby Joan", "Hey-girl Jill", "-lookin-good Jane".  The rule:
    drop everything before the last space in the first-name portion.

    Since full_name = first_name + " " + last_name, and last names are a
    single word, the algorithm is:

        words = full_name.split()
        if len(words) >= 3:
            return words[-2] + " " + words[-1]   # clean-first + last
        return full_name                          # already clean

    Examples (Access full_name → normalized):
        "-lookin-good Jane Doe"  →  "Jane Doe"
        "Baby Joan Roe"        →  "Joan Roe"
        "Hey-girl Jill Bloggs"     →  "Jill Bloggs"
        "Handsome John Doe"      →  "John Doe"
        "Jane Doe"               →  "Jane Doe"  (unchanged)

    Protect names may additionally carry a building/unit prefix
    (e.g. "116-4 Jill Bloggs").  Use matches_protect_name() to test
    whether a Protect display name corresponds to a normalized Access name.
    """
    words = full_name.strip().split()
    if len(words) >= 3:
        return f"{words[-2]} {words[-1]}"
    return full_name


def matches_protect_name(protect_name: str, normalized_access_name: str) -> bool:
    """
    Return True if a Protect display name corresponds to a normalized
    Access name.

    Protect names take one of two forms:
        "<building>-<unit> First Last"   e.g. "116-4 Jill Bloggs"
        "First Last"                     e.g. "Jill Bloggs"

    A match is found when the Protect name either equals the normalized
    name exactly, or ends with " <normalized_name>" (prefixed form).
    """
    return (
        protect_name == normalized_access_name
        or protect_name.endswith(f" {normalized_access_name}")
    )


# ── Top-log hit deduplication ─────────────────────────────────────────────────

# IDs of top_log hits already dispatched for correlation.  Kept as a plain set;
# entries older than _SEEN_ENTRY_TTL_SEC are never re-added because the top_log
# only holds recently-created records.
_seen_entry_ids: set = set()
_SEEN_ENTRY_TTL_SEC = 600   # 10 minutes — matches face-buffer TTL


async def _process_top_log_hits(
    session : aiohttp.ClientSession,
    hits    : list,
    source  : str,
) -> None:
    """
    Parse a list of top_log hits, deduplicate, and spawn correlation tasks.

    Hits arrive either as Elasticsearch-style {"_id":…, "_source":{…}} objects
    or as flat dicts.  Both shapes are handled.
    """
    for hit in hits:
        # Support Elasticsearch _source wrapper and plain flat dicts.
        entry_data = hit.get("_source") or hit

        entry_id = (
            hit.get("_id")
            or entry_data.get("id")
            or entry_data.get("unique_id")
            or entry_data.get("event_id")
            or ""
        )

        if entry_id and entry_id in _seen_entry_ids:
#            log.debug(f"[ACCESS] Duplicate entry skipped — id={entry_id[:8]}…")
            log.debug(f"[ACCESS] Duplicate entry skipped — id={entry_id}…")
            continue

        if entry_id:
            _seen_entry_ids.add(entry_id)

        # Log the raw hit once so we can verify the format.
#        log.info(f"[ACCESS] top_log hit ({source}): {json.dumps(hit)[:600]}")
        log.info(f"[ACCESS] top_log hit ({source}): {json.dumps(hit)}")

        actor            = entry_data.get("actor", {})
        event_obj        = entry_data.get("event", {})
        targets          = entry_data.get("target", [])
        event_object_id  = (
            hit.get("event_object_id")
            or entry_data.get("event_object_id")
            or (targets[0].get("id") if targets else None)
            or ""
        )

        # Build a synthetic envelope that _parse_access_entry already understands.
        synthetic = {
            "event"           : "access.logs.add",
            "event_object_id" : event_object_id,
            "data"            : {
                "_source": {
                    "actor"  : actor,
                    "event"  : event_obj,
                    "target" : targets,
                }
            },
        }

        entry = _parse_access_entry(synthetic)
        if entry:
            asyncio.create_task(_correlate(session, entry))
        else:
            log.info(
                f"[ACCESS] Hit not an access grant — "
                f"actor={actor}  event={event_obj}"
            )


async def _fetch_and_process_top_log(
    session     : aiohttp.ClientSession,
    source      : str,
    delay_sec   : float = 0.0,
) -> None:
    """
    Query the REST /access/top_log endpoint and process any new hits.

    delay_sec lets callers debounce bursts of WS events (e.g. the 3–4
    location.update messages that fire per door open) before hitting the API.
    """
    if delay_sec:
        await asyncio.sleep(delay_sec)
    try:
        async with session.get(
            f"{_ACCESS_BASE}/access/top_log",
            ssl     = _ssl,
            headers = _HEADERS,
        ) as resp:
            if resp.status == 200:
                data = await resp.json()
                hits = (data.get("data") or {}).get("hits") or []
                if hits:
                    log.info(f"[ACCESS] top_log REST ({source}): {len(hits)} hit(s).")
                    await _process_top_log_hits(session, hits, source)
    except Exception as exc:
        log.debug(f"top_log fetch error ({source}): {exc}")


async def access_top_log_poller(session: aiohttp.ClientSession) -> None:
    """
    Poll GET /access/top_log every 30 s as a safety net.
    Catches entries that arrive while the WebSocket is reconnecting.
    """
    while True:
        await asyncio.sleep(30)
        await _fetch_and_process_top_log(session, "rest-poll")


# ── Access WebSocket subscriber ───────────────────────────────────────────────

def _parse_access_entry(data: dict) -> Optional[AccessEntry]:
    """
    Extract an AccessEntry from an Access WebSocket event.

    Confirmed envelope (Access firmware v4.2.16):
        {"event": "access.logs.add",
         "data": {
           "_id": "…",
           "@timestamp": "…",
           "_source": {
             "actor": {"id": "…", "type": "user", "display_name": "Jane Doe"},
             "event": {"type":            "access.door.unlock",
                       "display_message": "Access Granted",
                       "result":          "ACCESS",
                       "published":       1775228318000},
             "target": [{"type": "door", "display_name": "110 Front Door"}]
           }
         }}

    REX (Request to Exit — inside button press) events arrive with
    display_name "N/A" and are skipped since no person can be identified.
    """
    event_name = data.get("event", "")

    # Only process log events (door access).
    if "logs" not in event_name and "access" not in event_name:
        log.debug(f"[ACCESS] skipped non-log event: {event_name!r}")
        return None

    source  = data.get("data", {}).get("_source") or data.get("data") or data
    event   = source.get("event", {})
    actor   = source.get("actor", {})
    targets = source.get("target", [])

    result = (
        event.get("result")
        or data.get("result")
        or source.get("result")
        or ""
    )

    # Accept both the documented "Access Granted" and the actual firmware
    # value "ACCESS".  Anything else (denied, error, etc.) is skipped.
    if result not in ("ACCESS", "Access Granted", "GRANTED"):
        log.debug(f"[ACCESS] skipped — result={result!r}")
        return None

    raw_name = (
        actor.get("display_name")
        or data.get("actor_name")
        or ""
    ).strip()

    # "N/A" is the placeholder Access uses for REX (Request to Exit —
    # someone pushed the inside button).  No person to correlate.
    if not raw_name or raw_name.upper() == "N/A":
        log.debug(f"[ACCESS] skipped — actor is {raw_name!r} (REX or anonymous).")
        return None

    person_name = _normalize_access_name(raw_name)

    person_id = actor.get("id") or data.get("actor_id") or ""
    door_name = (
        (targets[0].get("display_name") if targets else None)
        or data.get("door_name")
        or "Unknown Door"
    )

    # Resolve hardware device name (e.g. "UA-HUB-DOOR-EC91") to the
    # configured alias (e.g. "116 Front Door") using IDs from the target
    # object or the event_object_id field, whichever is available.
    candidate_ids = [
        (targets[0].get("id") or targets[0].get("unique_id")) if targets else None,
        data.get("event_object_id"),
        (data.get("data") or {}).get("event_object_id"),
    ]
    for cid in candidate_ids:
        if cid and cid in _access_device_map:
            door_name = _access_device_map[cid]
            break

    ts_raw = (
        event.get("published")
        or data.get("timestamp_ms")
        or int(time.time() * 1000)
    )
    ts_ms = int(ts_raw)
    if ts_ms < 1_000_000_000_000:   # normalize epoch-seconds → milliseconds
        ts_ms *= 1000

    # The reader that authenticated the person is a Protect camera: the
    # `activities_resource` target carries its id in `alternate_id`.  This lets
    # the teach prefer that camera's face event and disambiguate multi-person
    # frames (the authenticator is the face at the reader).
    reader_camera_id = ""
    for tg in targets:
        if tg.get("type") == "activities_resource":
            reader_camera_id = tg.get("alternate_id") or ""
            break

    return AccessEntry(
        person_name  = person_name,
        raw_name     = raw_name,
        person_id    = person_id,
        door_name    = door_name,
        timestamp_ms = ts_ms,
        reader_camera_id = reader_camera_id,
    )


async def access_subscriber(
    session : aiohttp.ClientSession,
) -> None:
    """Connect to Access's notification WebSocket; reconnect automatically."""
    while True:
        try:
            log.info("Connecting to Access notification WebSocket…")
            async with session.ws_connect(
                _ACCESS_WS,
                headers   = _HEADERS,
                ssl       = _ssl,
                heartbeat = 30,
            ) as ws:
                log.info("Access WebSocket connected.")
                async for msg in ws:
                    if msg.type == aiohttp.WSMsgType.TEXT:
                        raw = msg.data
                        if raw == '"Hello"' or raw.strip() == '"Hello"':
                            continue  # keepalive ping

                        try:
                            data = json.loads(raw)
                        except json.JSONDecodeError:
                            continue

                        event_name = data.get("event", "")

                        # ── Silence routine chatter ───────────────────────
                        if event_name in (
                            "access.data.device.update",
                            "access.data.v2.device.update",
                            "access.base.info",
                            "access.data.wallet_status.update",
                            "access.logs.insights.add",   # redundant — access.logs.add covers it
                            "access.dps_change",          # door-position sensor open/close
                        ):
                            log.debug(f"[ACCESS] ignored: {event_name!r}")
                            continue

                        # ── Door open/lock-state change → fetch top_log ────
                        # These events fire 3-4 times per door event, so use
                        # a 1 s debounce delay to consolidate into one query.
                        if event_name in (
                            "access.data.location.update",
                            "access.data.v2.location.update",
                        ):
                            door = (data.get("data") or {}).get(
                                "name",
                                (data.get("data") or {}).get("alias", "?"),
                            )
                            log.info(f"[ACCESS] Door event — {door!r}. Querying top_log…")
                            asyncio.create_task(
                                _fetch_and_process_top_log(session, "location-update", delay_sec=1.0)
                            )
                            continue

                        # ── top_log.update → always re-query REST ──────────
                        # WS hits are consistently empty on this firmware;
                        # the data is only available via the REST endpoint.
                        if event_name == "access.data.top_log.update":
                            asyncio.create_task(
                                _fetch_and_process_top_log(session, "top_log-update")
                            )
                            continue

                        # ── Any other unknown event: log for visibility ─────
                        log.info(
                            f"[ACCESS  WS] event={event_name!r}  "
#                            f"raw={raw[:300]}"
                            f"raw={raw}"
                        )
                        entry = _parse_access_entry(data)
                        if entry:
                            asyncio.create_task(
                                _correlate(session, entry)
                            )
                    elif msg.type in (
                        aiohttp.WSMsgType.ERROR,
                        aiohttp.WSMsgType.CLOSED,
                    ):
                        log.warning(f"Access WS closed: {ws.exception()}")
                        break
        except Exception as exc:
            log.error(f"Access WS error: {exc}")
        log.info("Access WS: reconnecting in 10 s…")
        await asyncio.sleep(10)


# ── Correlation logic ─────────────────────────────────────────────────────────

async def _fetch_face_thumbnail(
    session  : aiohttp.ClientSession,
    event_id : str,
) -> Optional[bytes]:
    """Try both the integration-v1 and legacy API paths for the thumbnail."""
    urls = [
        f"{_PROTECT_BASE}/events/{event_id}/thumbnail",
        f"https://{UNVR_HOST}/proxy/protect/api/events/{event_id}/thumbnail",
    ]
    for url in urls:
        try:
            async with session.get(url, ssl=_ssl, headers=_HEADERS) as resp:
                if resp.status == 200:
                    ctype = resp.headers.get("Content-Type", "")
                    if "image" in ctype:
                        return await resp.read()
                    log.debug(f"Thumbnail at {url}: non-image content-type {ctype!r}")
        except Exception as exc:
            log.debug(f"Thumbnail fetch failed ({url}): {exc}")
    return None


async def _fetch_access_avatar(
    session   : aiohttp.ClientSession,
    person_id : str,
) -> Optional[bytes]:
    """Fetch the Access profile photo for a user (if one is set)."""
    if not person_id:
        return None
    url = f"{_ACCESS_BASE}/user/{person_id}"
    try:
        async with session.get(url, ssl=_ssl, headers=_HEADERS) as resp:
            if resp.status != 200:
                return None
            user = (await resp.json()).get("data") or {}
            avatar_path = user.get("avatar_relative_path", "").strip()
            if not avatar_path:
                return None

            avatar_url = f"https://{UNVR_HOST}{avatar_path}"
            async with session.get(avatar_url, ssl=_ssl, headers=_HEADERS) as img_resp:
                if img_resp.status == 200:
                    return await img_resp.read()
    except Exception as exc:
        log.debug(f"Access avatar fetch failed (person_id={person_id}): {exc}")
    return None


async def _correlate(
    session : aiohttp.ClientSession,
    entry   : AccessEntry,
) -> None:
    """
    Background task: wait for the search window to elapse, search the Protect
    face-event buffer, and save any correlated results to OUTPUT_DIR.
    """
    ts_str = datetime.fromtimestamp(
        entry.timestamp_ms / 1000
    ).strftime("%Y-%m-%d %H:%M:%S")

    name_display = (
        f"{entry.person_name!r}  (Access: {entry.raw_name!r})"
        if entry.person_name != entry.raw_name
        else repr(entry.person_name)
    )
    log.info(
        f"[ACCESS] Entry — person={name_display}  "
        f"door={entry.door_name!r}  time={ts_str}"
    )
    log.info(
        f"  Waiting {FACE_SEARCH_POST_SEC}s for Protect to complete "
        f"face detection…"
    )

    await asyncio.sleep(FACE_SEARCH_POST_SEC)

    matches = _face_buffer.find_matches(
        entry,
        pre_ms  = FACE_SEARCH_PRE_SEC  * 1000,
        post_ms = FACE_SEARCH_POST_SEC * 1000,
    )

    if not matches:
        log.info(
            f"  No Protect face events found in "
            f"[−{FACE_SEARCH_PRE_SEC}s…+{FACE_SEARCH_POST_SEC}s] window "
            f"for {entry.person_name!r}."
        )
        return

    log.info(
        f"  Correlated {len(matches)} Protect face event(s) "
        f"with {entry.person_name!r}."
    )

    # ── Teach Protect the Access-confirmed identity (Access prevails) ──────────
    # Prefer the face event on the reader camera that authenticated the person
    # (that frame definitely contains them, at the reader); otherwise the closest
    # match in time.  The teach routine applies the distinct-people gate.
    if TEACH_ENABLED:
        reader = entry.reader_camera_id
        pool = [m for m in matches if reader and m.camera_id == reader] or matches
        best = min(pool, key=lambda m: abs(m.start_ms - entry.timestamp_ms))
        await _teach_from_match(entry, best)

    safe_name = "".join(
        c if c.isalnum() or c in "-_" else "_" for c in entry.person_name
    )
    safe_time = datetime.fromtimestamp(
        entry.timestamp_ms / 1000
    ).strftime("%Y%m%d_%H%M%S")
    stem = f"{safe_time}_{safe_name}"

    # ── Fetch Access profile avatar ───────────────────────────────────────────
    avatar_bytes    = None if DRY_RUN else await _fetch_access_avatar(session, entry.person_id)
    avatar_filename = None
    if DRY_RUN:
        log.info("  Access avatar  → [DRY-RUN] not fetched.")
    elif avatar_bytes:
        avatar_filename = f"{stem}.access_avatar.jpg"
        (OUTPUT_DIR / avatar_filename).write_bytes(avatar_bytes)
        log.info(f"  Access avatar  → {OUTPUT_DIR / avatar_filename}")
    else:
        log.info("  Access avatar  → not set for this user.")

    # ── Fetch Protect face thumbnails ─────────────────────────────────────────
    protect_records = []
    for idx, fe in enumerate(matches, start=1):
        fe_ts    = datetime.fromtimestamp(
            fe.start_ms / 1000
        ).strftime("%H:%M:%S.%f")[:-3]
        delta    = (fe.start_ms - entry.timestamp_ms) / 1000
        sign     = "+" if delta >= 0 else ""
#        cam_name = _protect_camera_map.get(fe.camera_id, fe.camera_id[:8] + "…")
        cam_name = _protect_camera_map.get(fe.camera_id, fe.camera_id + "…")
        log.info(
            f"  Face event {idx}/{len(matches)}: "
#            f"id={fe.event_id[:8]}…  camera={cam_name!r}  "
            f"id={fe.event_id}…  camera={cam_name!r}  "
            f"time={fe_ts}  (Δ{sign}{delta:.1f}s)"
        )

        thumb_bytes    = None if DRY_RUN else await _fetch_face_thumbnail(session, fe.event_id)
        thumb_filename = None
        if DRY_RUN:
            log.info("    Protect thumbnail → [DRY-RUN] not fetched.")
        elif thumb_bytes:
            thumb_filename = f"{stem}_face_{idx:02d}.jpg"
            (OUTPUT_DIR / thumb_filename).write_bytes(thumb_bytes)
            log.info(f"    Protect thumbnail → {OUTPUT_DIR / thumb_filename}")
        else:
            log.info("    Protect thumbnail → not available.")

        protect_records.append({
            "event_id"           : fe.event_id,
            "camera_id"          : fe.camera_id,
            "camera_name"        : _protect_camera_map.get(fe.camera_id, ""),
            "start_ms"           : fe.start_ms,
            "end_ms"             : fe.end_ms,
            "smart_detect_types" : fe.smart_detect_types,
            "delta_sec"          : round(delta, 3),
            "thumbnail_file"     : thumb_filename,
        })

    # ── Write JSON correlation record ─────────────────────────────────────────
    record = {
        "access_entry": {
            "person_name"  : entry.person_name,
            "raw_name"     : entry.raw_name,
            "person_id"    : entry.person_id,
            "door_name"    : entry.door_name,
            "timestamp_ms" : entry.timestamp_ms,
            "timestamp"    : ts_str,
            "avatar_file"  : avatar_filename,
        },
        "search_window_sec": {
            "pre"  : FACE_SEARCH_PRE_SEC,
            "post" : FACE_SEARCH_POST_SEC,
        },
        "protect_face_events": protect_records,
    }
    if DRY_RUN:
        log.info(
            f"  [DRY-RUN] Correlation record (not written):\n"
            + json.dumps(record, indent=4)
        )
    else:
        record_path = OUTPUT_DIR / f"{stem}.json"
        record_path.write_text(json.dumps(record, indent=2))
        log.info(f"  Correlation record → {record_path}")


# ── Face teaching: write the Access-confirmed identity onto the Protect face ───

class _AdminClient:
    """
    Lazily-authenticated admin session for the PRIVATE recognition API.

    The integration X-API-KEY cannot reach /proxy/protect/api/...; recognition
    reads (and the future write) require a username/password session that yields
    an X-CSRF-Token + TOKEN cookie.  This client owns its own aiohttp session
    (separate from the integration session) with an unsafe cookie jar so cookies
    are stored even when PRIVATE_HOST is a bare IP address.
    """

    def __init__(self) -> None:
        self.session: Optional[aiohttp.ClientSession] = None
        self.csrf:    Optional[str]                   = None

    async def _ensure(self) -> bool:
        if self.session is not None and self.csrf:
            return True
        if not PRIVATE_USER or not PRIVATE_PASS:
            log.warning(
                "[TEACH] PROTECT_USER/PROTECT_PASS not set — recognition API "
                "unavailable; cannot teach."
            )
            return False
        if self.session is None:
            self.session = aiohttp.ClientSession(
                connector  = aiohttp.TCPConnector(ssl=_ssl),
                cookie_jar = aiohttp.CookieJar(unsafe=True),
            )
        try:
            async with self.session.post(
                f"https://{PRIVATE_HOST}/api/auth/login",
                json = {"username": PRIVATE_USER, "password": PRIVATE_PASS},
                ssl  = _ssl,
            ) as resp:
                if resp.status not in (200, 201):
                    log.error("[TEACH] admin login failed: HTTP %s", resp.status)
                    return False
                self.csrf = (
                    resp.headers.get("X-CSRF-Token")
                    or resp.headers.get("x-csrf-token")
                )
                return bool(self.csrf)
        except Exception as exc:
            log.error("[TEACH] admin login error: %s", exc)
            return False

    async def get_json(self, path: str) -> Optional[dict | list]:
        """GET a private-API path as JSON, re-authenticating once on 401."""
        if not await self._ensure():
            return None
        for attempt in (1, 2):
            try:
                async with self.session.get(
                    f"https://{PRIVATE_HOST}{path}",
                    headers = {"X-CSRF-Token": self.csrf or ""},
                    ssl     = _ssl,
                ) as resp:
                    if resp.status == 200:
                        return await resp.json(content_type=None)
                    if resp.status in (401, 403) and attempt == 1:
                        self.csrf = None
                        if not await self._ensure():
                            return None
                        continue
                    log.debug("[TEACH] GET %s → HTTP %s", path, resp.status)
                    return None
            except Exception as exc:
                log.debug("[TEACH] GET %s error: %s", path, exc)
                return None
        return None

    async def post(self, path: str, body: dict) -> Optional[tuple[int, str]]:
        """POST JSON to a private-API path; returns (status, text) or None.
        Re-authenticates once on 401/403."""
        if not await self._ensure():
            return None
        for attempt in (1, 2):
            try:
                async with self.session.post(
                    f"https://{PRIVATE_HOST}{path}",
                    headers = {
                        "X-CSRF-Token": self.csrf or "",
                        "Content-Type": "application/json",
                    },
                    json = body,
                    ssl  = _ssl,
                ) as resp:
                    if resp.status in (401, 403) and attempt == 1:
                        self.csrf = None
                        if not await self._ensure():
                            return None
                        continue
                    return resp.status, await resp.text()
            except Exception as exc:
                log.debug("[TEACH] POST %s error: %s", path, exc)
                return None
        return None

    async def close(self) -> None:
        if self.session is not None:
            await self.session.close()


_admin = _AdminClient()
_face_group_cache: Optional[list] = None


async def _resolve_target_group(normalized_name: str) -> tuple[Optional[str], Optional[str]]:
    """
    Find the Protect face group (known person) whose name corresponds to the
    Access-confirmed normalized name.  Protect names are "<unit> First Last".
    Returns (group_id, group_name) or (None, None) if the person has no group.
    """
    global _face_group_cache
    if _face_group_cache is None:
        data = await _admin.get_json(
            "/proxy/protect/api/recognition/face/groups"
            "?pageSize=200&orderBy=name&orderDirection=asc"
        )
        _face_group_cache = (data or {}).get("groups", []) if isinstance(data, dict) else []
    for g in _face_group_cache:
        gname = g.get("name") or g.get("matchedName") or ""
        if gname and matches_protect_name(gname, normalized_name):
            return g.get("id"), gname
    return None, None


async def _find_detection(group_id: str, cropped_id: str) -> Optional[str]:
    """
    Return the detection-record id in `group_id` whose thumbnailId == cropped_id
    (the croppedId carried on the event's face thumbnail).  Pages through the
    group's detections.  None if not found (e.g. Protect created no detection).
    """
    if not group_id or not cropped_id:
        return None
    page = 1
    while page <= 10:
        data = await _admin.get_json(
            f"/proxy/protect/api/recognition/face/groups/{group_id}"
            f"/detections?pageSize=50&page={page}"
        )
        if not isinstance(data, dict):
            return None
        for det in data.get("detections", []):
            if det.get("thumbnailId") == cropped_id:
                return det.get("id")
        if not (data.get("links") or {}).get("next"):
            break
        page += 1
    return None


async def _fetch_enriched_face_event(event_id: str, start_ms: int) -> Optional[dict]:
    """
    Re-fetch the face event via the LIST endpoint, which enriches face
    thumbnails with {name, group} (the single-event GET does NOT).  Searches a
    tight window around the event's start timestamp.
    """
    s = start_ms - 5_000
    e = start_ms + 60_000
    data = await _admin.get_json(
        f"/proxy/protect/api/events?start={s}&end={e}"
        f"&types=smartDetectZone&limit=100"
    )
    if isinstance(data, list):
        for ev in data:
            if ev.get("id") == event_id:
                return ev
    return None


async def _assign_detection_to_group(
    det_id      : Optional[str],
    cropped_id  : str,
    event_id    : str,
    current_gid : Optional[str],
    target_gid  : str,
) -> bool:
    """
    WRITE — push the Access-confirmed identity onto the Protect face.

    Two cases:
      • det_id is set  → REASSIGN an existing detection (Protect filed the face
                         under the wrong / an unnamed group) to target_gid.
      • det_id is None → ADD a new sample to target_gid from this thumbnail
                         (Protect did not recognise the face at all).

    Confirmed endpoint (mitmproxy capture of the Protect Faces UI, 2026-05-31):
      POST /proxy/protect/api/recognition/face/assign-group
      {"objectIds": [det_id], "groupId": target_gid}
    The same call serves both REASSIGN (det_id sits in the wrong/auto-cluster
    group) and ASSIGN (det_id is an as-yet-unnamed detection).  objectIds are
    detection ids (the `id` from /groups/{g}/detections, == the value the UI
    sends).  When det_id is None we have no object id to send — the truly-
    unrecognised "no detection at all" case can't be taught this way.
    """
    if not (TEACH_WRITE and WRITE_ENDPOINT_CONFIRMED) or DRY_RUN:
        return False
    if not det_id:
        log.warning(
            "[TEACH] no detection/object id (Protect created no detection) — "
            "cannot teach via assign-group."
        )
        return False
    result = await _admin.post(
        "/proxy/protect/api/recognition/face/assign-group",
        {"objectIds": [det_id], "groupId": target_gid},
    )
    if not result:
        log.error("[TEACH] assign-group POST got no response.")
        return False
    status, text = result
    if 200 <= status < 300:
        log.info("[TEACH] assign-group OK (HTTP %s) — detection %s → group %s.",
                 status, det_id[:8], target_gid)
        return True
    log.error("[TEACH] assign-group failed HTTP %s: %.200s", status, text)
    return False


def _face_metrics(t: dict) -> dict:
    """
    Distil a Protect face thumbnail into the fields the teach gate needs.

    name  = the RECOGNISED person's name, or None if Protect hasn't named the
            face (an auto-cluster group still has a `gid`, but no `name`).
    area / frontality / quality let us pick the authenticator in a crowd
    (the person at the reader is the biggest, most face-on, best-quality crop).
    """
    g     = t.get("group") or {}
    coord = t.get("coord") or [0, 0, 0, 0]
    attrs = t.get("attributes") or {}
    pose  = attrs.get("facePose") or {}
    name  = (t.get("name") or g.get("name") or "").strip() or None
    area  = (coord[2] * coord[3]) if len(coord) >= 4 else 0
    front = -(abs(pose.get("yaw") or 90) + abs(pose.get("pitch") or 90))  # closer to 0 = more frontal
    return {
        "gid":     g.get("id"),
        "name":    name,
        "area":    area,
        "front":   front,
        "quality": attrs.get("qualityScore") or 0,
        "cropped": t.get("croppedId") or "",
    }


async def _teach_from_match(entry: AccessEntry, fe: FaceEvent) -> None:
    """
    Given a correlated Access entry (deterministic identity) and the Protect
    face event it matched, attach the Access identity to the right Protect face.
    Access prevails.

    DISTINCT-PEOPLE gate (replaces the old "exactly one face thumbnail" rule,
    which over-skipped: ~50% of multi-thumbnail events are ONE person re-detected
    across the event window).  We count people by IDENTITY, not by thumbnail:
      • named faces with different names  = different people;
      • un-named (auto-cluster) faces     = candidate(s) for the Access person.
    Decisions:
      • No other named person present  → single-person scene (incl. the Access
        person re-detected): teach the best un-named crop.
      • Other named people present (a real group):
          - on the READER camera → teach the biggest/frontmost un-named crop
            (the authenticator is the face at the reader — trial heuristic);
          - any other camera     → skip (no reader anchor; single-person only).
    """
    ev = await _fetch_enriched_face_event(fe.event_id, fe.start_ms)
    if not ev:
        log.info("[TEACH] could not fetch enriched event %s — skip.", fe.event_id[:8])
        return

    faces = [
        _face_metrics(t)
        for t in (ev.get("metadata", {}).get("detectedThumbnails") or [])
        if t.get("type") == "face"
    ]
    if not faces:
        return

    target_gid, target_nm = await _resolve_target_group(entry.person_name)
    if not target_gid:
        log.info(
            "[TEACH] no Protect face group for Access %r — link the identity "
            "(or align the name) before teaching.", entry.person_name,
        )
        return

    # Faces Protect has confidently named as SOMEONE ELSE = other people present.
    distinct_others = {f["gid"] for f in faces if f["name"] and f["gid"] != target_gid}
    # Un-named (auto-cluster) crops = candidates to teach as the Access person.
    unnamed = [f for f in faces if not f["name"]]
    on_reader = bool(entry.reader_camera_id) and fe.camera_id == entry.reader_camera_id

    if not distinct_others:
        if not unnamed:
            log.info("[TEACH] Protect already agrees (%s) — nothing to teach.", target_nm)
            return
        scene = f"single person, {len(faces)} crop(s)"
    else:
        if not unnamed:
            log.info(
                "[TEACH] multi-person (%d other(s)); Access face already named or not "
                "separable — skip.", len(distinct_others))
            return
        if not on_reader:
            log.info(
                "[TEACH] multi-person (%d other(s)) on non-reader cam %s — skip "
                "(single-person rule off the reader).", len(distinct_others), fe.camera_id)
            return
        scene = f"reader-cam, {len(distinct_others)} other(s) → biggest/frontmost"

    # Pick the authenticator's crop: biggest, then most frontal, then best quality.
    pick = max(unnamed, key=lambda f: (f["area"], f["front"], f["quality"]))
    det_id = await _find_detection(pick["gid"], pick["cropped"]) if pick["gid"] else None
    if not det_id:
        log.info("[TEACH] %s: no detection for crop %s — skip.", scene, pick["cropped"])
        return

    do_write = TEACH_WRITE and not DRY_RUN
    log.info(
        "[TEACH] %s; ACCESS confirms %r → %s detection %s → group %s (%s).",
        scene, entry.person_name,
        "assigning" if do_write else "WOULD assign",
        det_id[:8], target_gid, target_nm,
    )
    if not do_write:
        log.info("[TEACH] no write performed (%s).",
                 "--dry-run" if (TEACH_WRITE and DRY_RUN) else "run with --teach-write to apply")
        return

    wrote = await _assign_detection_to_group(
        det_id, pick["cropped"], fe.event_id, pick["gid"], target_gid
    )
    if wrote:
        log.info("[TEACH] ✓ taught Protect: %s is now %s.", entry.person_name, target_nm)
    else:
        log.warning("[TEACH] write did NOT succeed for %s.", entry.person_name)


# ── Startup helpers ───────────────────────────────────────────────────────────

async def _log_cameras(session: aiohttp.ClientSession) -> None:
    """
    List all Protect cameras at startup so DOOR_CAMERA_MAP can be populated.
    Cameras with face-detection capability are highlighted.
    """
    try:
        async with session.get(
            f"{_PROTECT_BASE}/cameras",
            ssl     = _ssl,
            headers = _HEADERS,
        ) as resp:
            if resp.status != 200:
                log.warning(
                    f"Could not fetch Protect camera list (HTTP {resp.status})."
                )
                return
            cameras = await resp.json()
    except Exception as exc:
        log.warning(f"Camera list fetch failed: {exc}")
        return

    log.info(f"{'─'*68}")
    log.info(f"=== Protect cameras ({len(cameras)} found) ===")
    for cam in cameras:
        flags        = cam.get("featureFlags", {})
        face_capable = "face" in flags.get("smartDetectTypes", [])
        cam_id       = cam.get("id", "")
        cam_name     = cam.get("name", "")
        if cam_id and cam_name:
            _protect_camera_map[cam_id] = cam_name
        log.info(
            f"  {'[FACE]' if face_capable else '      '}  "
            f"id={cam_id}  name={cam_name!r}"
        )
    log.info(
        "  → Copy a camera id into DOOR_CAMERA_MAP to restrict matching "
        "to a specific camera."
    )


async def _log_access_doors(session: aiohttp.ClientSession) -> None:
    """List all Access door devices so DOOR_CAMERA_MAP keys can be confirmed."""
    try:
        async with session.get(
            f"{_ACCESS_BASE}/devices",
            ssl     = _ssl,
            headers = _HEADERS,
        ) as resp:
            if resp.status != 200:
                return
            data    = await resp.json()
            devices = data.get("data", [])
    except Exception as exc:
        log.warning(f"Access device list fetch failed: {exc}")
        return

    log.info(f"=== Access doors ({len(devices)} device(s) found) ===")
    for dev in devices:
        alias    = dev.get("alias") or dev.get("name", "")
        uid      = dev.get("unique_id", "")
        dev_type = dev.get("device_type", "")
        if uid and alias:
            _access_device_map[uid] = alias
        log.info(
            f"  alias={alias!r:35s}  type={dev_type}  "
            f"id={uid}"
        )
    log.info(
        "  → Use the alias (or name) as the key in DOOR_CAMERA_MAP."
    )
    log.info(f"{'─'*68}")


# ── Main ──────────────────────────────────────────────────────────────────────

async def main() -> None:
    global DRY_RUN, TEACH_ENABLED, TEACH_WRITE

    parser = argparse.ArgumentParser(
        description="Correlate UniFi Access door entries with Protect face detections."
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help=(
            "Run full correlation logic against both APIs but skip all file "
            "writes. Logs the normalized name and matched face events without "
            "saving thumbnails, avatars, or JSON records to disk."
        ),
    )
    parser.add_argument(
        "--teach",
        action="store_true",
        help=(
            "After each correlation, compare Protect's face recognition to the "
            "Access-confirmed identity and, when they disagree or Protect has no "
            "name, log the reassignment that would teach Protect (ACCESS PREVAILS). "
            "Reads the PRIVATE recognition API via an admin session "
            "(PROTECT_USER/PROTECT_PASS env vars, PROTECT_PRIVATE_HOST optional). "
            "Logs decisions only (DRY-RUN) unless --teach-write is also given."
        ),
    )
    parser.add_argument(
        "--teach-write",
        action="store_true",
        help=(
            "Implies --teach AND actually performs the write: "
            "POST /proxy/protect/api/recognition/face/assign-group to reassign the "
            "Protect detection to the Access-confirmed person. Honours the single-"
            "face safeguard. Without this, --teach only logs what it would do."
        ),
    )
    args         = parser.parse_args()
    DRY_RUN      = args.dry_run
    TEACH_WRITE  = args.teach_write
    TEACH_ENABLED = args.teach or TEACH_WRITE

    if DRY_RUN:
        log.info("═" * 68)
        log.info("DRY-RUN MODE — correlations logged but no files written.")
        log.info("═" * 68)
    else:
        OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    if TEACH_ENABLED:
        log.info("═" * 68)
        log.info("TEACH MODE — Access→Protect identity write-back ENABLED.")
        log.info(
            "  recognition host=%s  user=%s  writes=%s",
            PRIVATE_HOST,
            PRIVATE_USER or "(unset!)",
            "LIVE (assign-group)" if (TEACH_WRITE and WRITE_ENDPOINT_CONFIRMED)
            else "dry-run (decisions only)",
        )
        log.info("═" * 68)

    connector = aiohttp.TCPConnector(ssl=_ssl)
    session   = aiohttp.ClientSession(connector=connector)

    await _log_cameras(session)
    await _log_access_doors(session)

    log.info(f"Output directory : {OUTPUT_DIR.resolve()}" + (" (dry-run — writes skipped)" if DRY_RUN else ""))
    log.info(
        f"Search window    : "
        f"−{FACE_SEARCH_PRE_SEC}s before entry … "
        f"+{FACE_SEARCH_POST_SEC}s after entry"
    )
    if DOOR_CAMERA_MAP:
        log.info(f"Door→camera map  : {DOOR_CAMERA_MAP}")
    else:
        log.info(
            "Door→camera map  : (empty) — matching face events from all cameras"
        )
    log.info("Starting Access and Protect WebSocket subscribers…")

    try:
        await asyncio.gather(
            protect_subscriber(session),
            access_subscriber(session),
            access_top_log_poller(session),
        )
    except asyncio.CancelledError:
        pass
    finally:
        await session.close()
        await _admin.close()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        log.info("Shutting down.")
