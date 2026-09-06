#!/usr/bin/env python3
"""Shared plumbing for the correlator: configuration, the state directory,
database access and notifications.

Everything that depends on WHERE the code runs is configuration, not code:

  * secrets.env / correlator.env next to this file are loaded into the
    environment at import (variables already set in the environment win).
  * CORRELATOR_STATE_DIR is where run state lives (proposals, jobs, the undo
    log, operator overrides). Default: ./state next to the code.
  * CORRELATOR_PSQL is the command that reaches PostgreSQL. Default: the
    local socket as the postgres OS user, which is what the NVR offers. On a
    machine that only has network reach to the database you could point it at
    e.g. "psql -h nvr -U protect_ro" (with PGPASSWORD in secrets.env) or even
    "ssh nvr sudo -u postgres psql"; SQL is passed on stdin so either works.
  * Pushover credentials are PUSHOVER_TOKEN / PUSHOVER_USER; without them
    notify() prints to stderr instead of failing.
"""
import glob
import json
import os
import ssl
import shutil
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent


def _load_env(path):
    if not path.is_file():
        return
    for line in path.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            os.environ.setdefault(k.strip(), v.strip().strip("'\""))


_load_env(HERE / "correlator.env")
_load_env(HERE / "secrets.env")

STATE = Path(os.environ.get("CORRELATOR_STATE_DIR", HERE / "state")).expanduser()
try:
    STATE.mkdir(parents=True, exist_ok=True)
    STATE.chmod(0o700)          # proposals, jobs and overrides carry tenant names
except OSError as _exc:         # a read-only importer (e.g. --help as another user) should not die here
    sys.stderr.write("common: state dir %s not writable: %s\n" % (STATE, _exc))

PROTECT_DB_PORT = int(os.environ.get("PROTECT_DB_PORT", "5433"))       # unifi-protect, smart_detect_face
ACCESS_LOG_DB_PORT = int(os.environ.get("ACCESS_LOG_DB_PORT", "5432"))  # ulp-go-syslog (Access badge events)
PROTECT_DB = "unifi-protect"
FACE_DB = "smart_detect_face"
ACCESS_LOG_DB = "ulp-go-syslog"


def _default_psql():
    binary = shutil.which("psql") or next(iter(sorted(glob.glob("/usr/lib/postgresql/*/bin/psql"))), "psql")
    return ["sudo", "-u", "postgres", binary]


PSQL_CMD = os.environ.get("CORRELATOR_PSQL", "").split() or _default_psql()


def psql(port, db, sql, copy=False):
    """Run one statement and return its stdout as unaligned, tuples-only text.

    copy=True wraps it as COPY (...) TO STDOUT (tab-separated, no header),
    the fast path for bulk reads. The SQL travels on stdin, so the command
    may be local or remote. Raises RuntimeError on any failure: a silent
    empty result once passed for a quiet run for 29 days (see
    badge_correlate.py)."""
    stmt = "COPY (%s) TO STDOUT" % sql if copy else sql
    cmd = PSQL_CMD + ["-X", "-v", "ON_ERROR_STOP=1", "-tA", "-p", str(port), "-d", db]
    r = subprocess.run(cmd, input=stmt + "\n", capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError("psql failed (port=%s db=%s): %s"
                           % (port, db, (r.stderr or r.stdout).strip()[:300]))
    return r.stdout


def notify(msg, title="Face matcher", prio="0"):
    """Pushover, from wherever this runs. Falls back to stderr without creds."""
    tok, usr = os.environ.get("PUSHOVER_TOKEN"), os.environ.get("PUSHOVER_USER")
    if not (tok and usr):
        sys.stderr.write("notify (no Pushover credentials): [%s] %s\n" % (title, msg))
        return
    data = urllib.parse.urlencode({"token": tok, "user": usr, "title": title,
                                   "priority": str(prio), "message": msg}).encode()
    try:
        urllib.request.urlopen(
            urllib.request.Request("https://api.pushover.net/1/messages.json", data=data),
            timeout=20).read()
    except Exception as exc:  # a failed notification must not fail the run
        sys.stderr.write("notify failed: %s\n" % exc)


class ProtectSession:
    """Admin session for Protect's private API, standard library only.

    POST /api/auth/login yields a TOKEN cookie and an X-CSRF-Token; both are
    replayed EXPLICITLY on every request. Deliberately no cookie jar: jars
    differ between library versions (on the NVR, aiohttp 3.7's jar dropped
    the session, the client re-authenticated per request, and UniFi OS
    rate-limited the account -- "AUTHENTICATION_FAILED_LIMIT_REACHED").
    Re-authenticates at most once per call for the same reason."""

    def __init__(self, host=None, user=None, password=None):
        self.host = host or os.environ.get("PROTECT_HOST", "unvr.pc")
        self.user = user or os.environ.get("PROTECT_USER", "")
        self.password = password or os.environ.get("PROTECT_PASS", "")
        self.token = self.csrf = None
        self._ctx = ssl.create_default_context()          # self-signed console certificate
        self._ctx.check_hostname = False
        self._ctx.verify_mode = ssl.CERT_NONE

    def _request(self, method, path, body=None, timeout=30):
        data = json.dumps(body).encode() if body is not None else None
        h = {"Accept": "application/json"}
        if data is not None:
            h["Content-Type"] = "application/json"
        if self.csrf:
            h["X-CSRF-Token"] = self.csrf
        if self.token:
            h["Cookie"] = "TOKEN=" + self.token
        req = urllib.request.Request("https://%s%s" % (self.host, path), data=data, method=method, headers=h)
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=self._ctx) as r:
                return r.status, r.headers, r.read().decode(errors="replace")
        except urllib.error.HTTPError as exc:
            return exc.code, exc.headers, exc.read().decode(errors="replace")

    def login(self):
        if not (self.user and self.password):
            sys.stderr.write("protect: PROTECT_USER / PROTECT_PASS not set\n")
            return False
        st, hdr, body = self._request("POST", "/api/auth/login",
                                      {"username": self.user, "password": self.password})
        if st not in (200, 201):
            sys.stderr.write("protect login failed: HTTP %s %s\n" % (st, body[:120].replace("\n", " ")))
            return False
        self.csrf = hdr.get("X-Updated-Csrf-Token") or hdr.get("X-CSRF-Token")
        self.token = None
        for sc in hdr.get_all("Set-Cookie") or []:
            name, _, value = sc.split(";", 1)[0].partition("=")
            if name.strip() == "TOKEN":
                self.token = value.strip()
        if not (self.csrf and self.token):
            sys.stderr.write("protect login: no CSRF token or TOKEN cookie in the response\n")
        return bool(self.csrf and self.token)

    def post(self, path, body):
        """Returns (status, text), or None if no session could be established."""
        if self.token is None and not self.login():
            return None
        st, _, text = self._request("POST", path, body)
        if st in (401, 403):
            self.token = None
            if not self.login():
                return None
            st, _, text = self._request("POST", path, body)
        return st, text
