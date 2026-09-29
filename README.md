# owctl — OpenWrt fleet control + threat watch

Single-file backend (FastAPI) + zero-dependency dashboard. Manages multiple
OpenWrt boxes over **SSH** (primary) or the **LuCI API** (fallback), with
config-hygiene threat auditing, package upgrades, config backups, LAN sweep,
and configurable alerting.

## Run

```bash
cd owctl
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
python owctl.py                 # http://<this-host>:8090
```

Useful env: `OWCTL_HOST` (default 0.0.0.0), `OWCTL_PORT` (default 8090),
`OWCTL_DATA` (data dir, default ./data), `OWCTL_TOKEN` (optional bearer token
for all /api routes).

## Add devices

- **Manual**: Devices tab → + Add device (name, IPv4, role, access mode).
- **Sweep**: Sweep tab → enter `192.168.1.0/24` or `192.168.1.1-192.168.1.250`;
  live hosts come back with port hints; OpenWrt/LuCI boxes are flagged, one-click add.

Access modes:
- `ssh` — root key or password; most features (upgrades, backups, reboot, full audit).
- `luci` — LuCI web password; status + LuCI config backup + sysupgrade detection.

## Threat engine

Checks per device: telnet enabled, SSH password auth, firewall default
INPUT/FORWARD=ACCEPT, NTP disabled, clock drift, outdated packages, firmware
(sysupgrade) updates, WAN down, port forwards. New findings fire alerts once,
re-alert if they disappear and return. Scheduler re-audits every 30 min
(configurable in code via `audit_interval_min`).

## Alerting

Dashboard (always on), plus optional: Email (SMTP), Telegram (bot token +
chat_id), and a JSON Webhook. Minimum-severity threshold configurable.

## Files

- `owctl.py` — backend (API + scheduler)
- `static/index.html` — dashboard
- `data/` — sqlite DB, config backups, created at runtime

## Install via Hermes Agent

A Hermes Agent (this TUI or any profile with a terminal) can set this up on a
LAN machine in one pass. Give it the repo and it will run:

```bash
# on the LAN machine
git clone https://github.com/spidertje/owctl.git
cd owctl
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/python owctl.py            # dashboard on http://<host>:8090
```

Hermes-friendly run modes (terminal tool):
- Foreground while working: `terminal(command="cd owctl && .venv/bin/python owctl.py", background=true)` — the agent then opens `http://<host>:8090` via the browser tool, adds devices, pushes SSH keys, and configures alerting through the UI or the JSON API.
- Persistent daemon: wrap in systemd or run `terminal(..., background=true, notify_on_complete=true)`.

Agent workflow after boot:
1. `POST /api/devices` per box (or `POST /api/sweep` with a `spec` like `192.168.1.0/24`).
2. `POST /api/devices/{id}/test` to verify credentials surface immediately.
3. `POST /api/devices/{id}/push-key` so subsequent access is key-only.
4. `POST /api/devices/{id}/check` to run the threat audit; review `GET /api/findings`.
5. `PUT /api/alerts/config` to enable Email / Telegram / Webhook channels.
6. Optional bearer token: set `OWCTL_TOKEN=<secret>` before starting, then send
   `Authorization: Bearer <secret>` on every `/api/*` call.
