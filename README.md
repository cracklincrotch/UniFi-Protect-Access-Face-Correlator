# UniFi Protect / Access face correlator

Turns UniFi Access badge events into named faces in UniFi Protect, and keeps
Protect's own face matcher useful. One tree, one configuration; nothing in it
cares which machine it runs on. The only thing that decides *where* it can run
is what the machine can reach:

| needs                         | used by                                   |
|-------------------------------|-------------------------------------------|
| Protect's PostgreSQL          | `badge_correlate.py`, `nightly_scan.py`, `ops/` |
| Protect's HTTPS API           | `face_auto_label.py`, `access_protect_correlator.py` |
| Pushover (outbound HTTPS)     | `face_auto_label.py`                      |

The NVR has all three, so the whole pipeline runs there. A box with only API
reach can still run the apply step if it is handed the database by other
means (`CORRELATOR_PSQL`, below).

## Pieces

- `common.py` — configuration, the state directory, `psql()`, `notify()`.
- `badge_correlate.py` — pairs unnamed face detections with Access door-unlock
  events (±3 s, reader/exterior cameras only, several ambiguity guards), maps
  badge names to Protect groups, writes `state/badge-proposals.json`.
- `nightly_scan.py` — embedding matcher: per-person centroids from named
  reference crops, z-scored against a background, writes `state/job.json`.
- `face_auto_label.py` — the scheduled job: runs the two steps, applies the
  batches to Protect through an admin session, appends
  `state/face-auto-label.jsonl` (one undo record per batch), sends one
  Pushover summary. Dry run without `--apply`.
- `access_protect_correlator.py` — the original live correlator/daemon and the
  library the job uses for the Protect admin session.
- `ops/` — NVR-side units: `face-auto-label.{service,timer}` (the schedule),
  `rebuild-face-identities.sh` + `face-identity-rebuild.{service,timer}`
  (repopulates Protect's face-matcher reference table, which the
  ai-feature-console clears on every start), `face-census.sh` +
  `face-census.{service,timer}` (hourly counts of every face store, for drop
  detection), and the launchd plist that ran the job from a Mac.
- `legacy/` — earlier one-off tools, kept for reference, not wired.

## Configuration

Two files next to the code, both loaded into the environment at import; real
environment variables take precedence.

- `secrets.env` (mode 600, never committed; see `secrets.env.example`):
  `PROTECT_HOST`, `PROTECT_API_KEY` (integration key, reads), `PROTECT_USER`
  / `PROTECT_PASS` (an admin account: the private recognition API and the
  assign-group write need a session), `PUSHOVER_TOKEN` / `PUSHOVER_USER`.
- `correlator.env` (optional; see `correlator.env.example`):
  `CORRELATOR_STATE_DIR` (default `./state`), `CORRELATOR_PSQL` (default
  `sudo -u postgres psql`, the local socket), `PROTECT_DB_PORT` (5433),
  `ACCESS_LOG_DB_PORT` (5432).

`state/` holds the run state and the operator's inputs, all of which contain
tenant names and stay out of git: `namemap-overrides.json` (badge name →
Protect group, wins over token matching), `vicinity_cameras.json` (manual
door → camera pairings; keys starting with `_` are parked), `rejected.json`
(detection ids never to propose), the generated `badge-proposals.json` and
`job.json`, and the undo log.

## Running it on the NVR (real hardware or the VM)

The scheduled job uses only the Python standard library, so nothing has to be
installed on the console. Keep everything under `/data`: on a UniFi OS console
a firmware update replaces the root filesystem, and `/data` is what survives.

```
mkdir -p /data/face-correlator && cd /data/face-correlator
curl -sL https://github.com/cracklincrotch/UniFi-Protect-Access-Face-Correlator/archive/refs/heads/main.tar.gz | tar -xz --strip-components=1
cp secrets.env.example secrets.env && chmod 600 secrets.env     # fill in
mkdir -p state && chmod 700 state   # put namemap-overrides.json / vicinity_cameras.json / rejected.json INTO state/ if you have them
python3 face_auto_label.py          # dry run
ops/install.sh                      # writes the two unit files, enables the timer
```

**After every firmware / UniFi OS update, run `ops/install.sh` again.** That
is the only piece an update removes (the unit files live on the root
filesystem). There is no supported persistent boot hook on stock UniFi OS; if
you use the community `udm-boot` package, a one-line script in
`/data/on_boot.d/` calling `ops/install.sh` closes the gap, but whether that
package itself survives a given update is not something this README can
promise.

The census timer in `ops/` installs the same way (it is monitoring, optional).
The identity-rebuild timer is shipped but intentionally not enabled: Protect
7.2 keeps that reference table empty by design, so the 7.1-era workaround is
parked until it is needed again. `access_protect_correlator.py`, the live
correlator/daemon, is the one piece that needs `aiohttp` (WebSockets); the
scheduled job does not import it.
