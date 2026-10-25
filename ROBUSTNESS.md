# owctl — robustness & supervision

owctl used to run as a bare `python owctl.py`: any crash, port conflict, or
parent-shell death killed it with no restart and no trace. This document
explains the robustness layer added in 2026-10 and how to run owctl as a
managed service on macOS or Linux.

## What changed (code, all in `owctl.py`)

| Area | Change | Why |
|------|--------|-----|
| **Logging** | Rotating log at `<DATA_DIR>/owctl.log` (override with `OWCTL_LOG`), `faulthandler` on, all `owctl`/`uvicorn`/`fastapi` loggers attached | A crash now leaves a traceback in a file instead of an unwatched terminal. |
| **Startup diagnostics** | `_startup_diagnostics()` + `_port_in_use()` run before `uvicorn.bind` | "Port already in use", "data dir not writable", "no TLS cert" are now one-line human reasons + exit codes (2 = env problem, 3 = port busy, 4 = server crash), not a bare traceback. |
| **Health endpoint** | `GET /api/health` (public, no auth) | Supervisors and `curl` can tell "dead" from "alive but slow". |
| **Global exception handler** | Uncaught errors → structured 500 JSON + full traceback to the log | A bad handler can no longer return a bare ASGI error or kill the process. |
| **Thread pool** | anyio default pool raised 40 → 200, `uvicorn.limit_concurrency=1000` | A fleet upgrade + scheduler + sweep no longer exhaust the pool and queue requests forever (the "looks dead" symptom). |
| **Rate limiter** | LRU eviction instead of `clear()` when the key cap is hit | A burst of distinct client IPs can no longer wipe everyone's counters (DoS window). |
| **DB backup** | `_db_backup()` via `VACUUM INTO`, keeps 14 newest | A consistent snapshot every audit cycle; a corrupt DB is recoverable. |
| **Retention** | `_prune_retention()` bounds findings/api_audit/config_history/heartbeats/actions | The unbounded tables no longer grow forever (disk fill → write failures → crash). |
| **SQLite** | `WAL` + `busy_timeout=10s` | Readers no longer block on the writer; a locked DB waits instead of raising. |
| **Graceful shutdown** | SIGTERM/SIGINT sets `_shutdown_event`, scheduler exits promptly, log line emitted | A supervisor stop is clean, not a hard kill mid-SSH. |
| **Scheduler** | Logs every cycle (start/finish, online/offline counts, per-device failures) | A stalled scheduler is visible in the log instead of silent. |
| **Deps** | `requirements.txt` pinned to tested versions (major-capped) | A fresh `pip install` can no longer pull a breaking new major. |

## Running it as a service (pick one)

All three options auto-restart on crash and write the same `owctl.log`.

### 1. `launch.sh` — simplest, any POSIX shell (macOS + Linux)

```bash
./launch.sh                 # foreground; Ctrl-C to stop
# or background:
nohup ./launch.sh >/dev/null 2>&1 &
# stop it:
kill "$(cat data/.owctl-supervisor.pid)"
```

### 2. `com.spidertje.owctl.plist` — macOS (auto-start at login, recommended on 179)

```bash
# edit the paths in the plist if yours differ, then:
mkdir -p ~/Library/LaunchAgents
cp com.spidertje.owctl.plist ~/Library/LaunchAgents/
launchctl load ~/Library/LaunchAgents/com.spidertje.owctl.plist
# stop:
launchctl unload ~/Library/LaunchAgents/com.spidertje.owctl.plist
# logs: data/owctl.log  (+ launchd stdout/stderr in the same dir)
```

### 3. `owctl.service` — Linux (auto-start at boot)

```bash
# edit User=/paths in the unit if they differ, then:
sudo cp owctl.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now owctl
# stop:
sudo systemctl stop owctl
# logs: journalctl -u owctl   AND   data/owctl.log
```

## Verifying it's healthy

```bash
curl -sk https://192.168.55.179:8090/api/health
# {"ok": true, "uptime_s": 12345}
```

`ok` proves the process is up *and* can open the DB. `uptime_s` tells you how
long the current process has been running — a small value right after an
incident means it just restarted (check `owctl.log` for why).

## What to look at when it "quits" again

1. `tail -50 data/owctl.log` — the crash traceback, the startup failure reason,
   or the "owctl stopped" line are all there now.
2. `data/owctl.db-*` — the most recent automatic backup, to restore if the
   DB was corrupted.
3. `data/.owctl-supervisor.pid` / `launchctl list` / `systemctl status owctl`
   — which supervisor is (or isn't) keeping it alive.
