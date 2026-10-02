#!/usr/bin/env python3
"""owctl — centralized control + threat detection for OpenWrt devices.

Single-file backend: device registry (manual + sweep), status gathering over
SSH or the LuCI API, config-hygiene threat audit, package/firmware updates,
config backups, and configurable alerting (dashboard / email / Telegram / webhook).

Run:  python owctl.py   (serves API + dashboard, default 0.0.0.0:8090)
"""
import base64
import json
import os
import re
import smtplib
import socket
import sqlite3
import ssl
import threading
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from email.message import EmailMessage

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

BASE = os.path.dirname(os.path.abspath(__file__))
HOST = os.environ.get("OWCTL_HOST", "0.0.0.0")
PORT = int(os.environ.get("OWCTL_PORT", "8090"))
DATA_DIR = os.environ.get("OWCTL_DATA", os.path.join(BASE, "data"))
DB_PATH = os.path.join(DATA_DIR, "owctl.db")
BACKUP_DIR = os.path.join(DATA_DIR, "backups")
os.makedirs(BACKUP_DIR, exist_ok=True)

SEV_RANK = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


# ---------------------------------------------------------------- database
_LOCK = threading.Lock()


def db():
    c = sqlite3.connect(DB_PATH, check_same_thread=False)
    c.row_factory = sqlite3.Row
    return c


def q(sql, args=()):
    with _LOCK:
        c = db()
        rows = [dict(r) for r in c.execute(sql, args).fetchall()]
        c.commit()
        c.close()
        return rows


def execute(sql, args=()):
    with _LOCK:
        c = db()
        last = c.execute(sql, args).lastrowid
        c.commit()
        c.close()
        return last


def init_db():
    execute("""CREATE TABLE IF NOT EXISTS devices(
        id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, host TEXT UNIQUE, role TEXT,
        access TEXT, ssh_port INTEGER, ssh_user TEXT, ssh_password TEXT, key_path TEXT,
        luci_user TEXT, luci_pass TEXT, status TEXT DEFAULT 'unknown',
        last_checked TEXT, added_at TEXT)""")
    try:
        execute("ALTER TABLE devices ADD COLUMN luci_port INTEGER")
    except sqlite3.OperationalError:
        pass
    execute("""CREATE TABLE IF NOT EXISTS findings(
        id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, device_id INTEGER, device_name TEXT,
        rule_id TEXT, severity TEXT, message TEXT, detail TEXT, rec TEXT)""")
    execute("""CREATE TABLE IF NOT EXISTS active_findings(
        device_id INTEGER, rule_id TEXT, severity TEXT, message TEXT, detail TEXT, rec TEXT, ts TEXT,
        PRIMARY KEY(device_id, rule_id))""")
    execute("""CREATE TABLE IF NOT EXISTS alert_log(
        id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, device TEXT, severity TEXT, rule_id TEXT,
        message TEXT, channels TEXT)""")
    execute("""CREATE TABLE IF NOT EXISTS backups(
        id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, device_id INTEGER, device_name TEXT,
        kind TEXT, path TEXT, size INTEGER)""")
    execute("""CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value TEXT)""")


def get_setting(k, d=None):
    r = q("SELECT value FROM settings WHERE key=?", (k,))
    return r[0]["value"] if r else d


def set_setting(k, v):
    execute("INSERT INTO settings(key,value) VALUES(?,?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value", (k, str(v)))


# ------------------------------------------------------- OpenWrt: SSH backend
GATHER_SCRIPT = r"""
echo '##release##'; cat /etc/openwrt_release 2>/dev/null | tr '\n' ' '
echo '##model##'; sed -n 's/.*"hostname"[^"]*"\([^"]*\)".*/\1/p' /etc/board.json 2>/dev/null
echo '##date##'; date '+%Y-%m-%d %H:%M:%S'
echo '##uptime##'; awk '{print int($1)}' /proc/uptime
echo '##load##'; cut -d' ' -f1-3 /proc/loadavg
echo '##mem##'; grep -E 'MemTotal|MemFree' /proc/meminfo | awk '{printf "%s=%s ", $1, $2}'
echo '##disk##'; df -h /overlay 2>/dev/null | awk 'NR==2 {print $2" used="$5" free="$4}'
echo '##clients##'; iwinfo 2>/dev/null | grep 'Associated STAs' | awk '{s+=$3} END{print s+0}'
echo '##wan##'; ubus call network.status wan 2>/dev/null | head -c 300
echo '##fw##'; printf 'in=%s fwd=%s out=%s\n' "$(uci -q get firewall.@defaults[0].input)" "$(uci -q get firewall.@defaults[0].forward)" "$(uci -q get firewall.@defaults[0].output)"
echo '##dropbear##'; printf 'pwauth=%s port=%s\n' "$(uci -q get dropbear.@dropbear[0].PasswordAuth)" "$(uci -q get dropbear.@dropbear[0].Port)"
echo '##listeners##'; netstat -tln 2>/dev/null | awk 'NR>1 {n=split($4,a,":"); if (a[n]~/^[0-9]+$/) print a[n]}' | sort -un | tr '\n' ' '
echo '##ntp##'; uci -q get system.ntp.enabled
echo '##redirects##'; i=0; while uci -q get "firewall.@redirect[$i].name" >/dev/null 2>&1; do printf '%s %s %s\n' "$i" "$(uci -q get "firewall.@redirect[$i].name")" "$(uci -q get "firewall.@redirect[$i].dest_port")"; i=$((i+1)); done
echo '##upgradable##'; opkg list-upgradable 2>/dev/null
echo '##end##'
"""


def _parse_sections(raw):
    sections, cur = {}, None
    for line in raw.splitlines():
        m = re.match(r'^##(\w+)##$', line.strip())
        if m:
            cur = m.group(1)
            sections[cur] = []
        elif cur is not None:
            sections[cur].append(line)
    # Join multi-line sections with a NEWLINE (not a space): sections that hold
    # one record per line (upgradable packages, port redirects) must keep their
    # line structure so _build_status can splitlines() them back into records.
    return {k: "\n".join(v).strip() for k, v in sections.items()}


def _ssh_connect(dev):
    import paramiko
    import socket as _socket
    from paramiko.ssh_exception import AuthenticationException as SSHAuthError
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    kw = dict(hostname=dev["host"], port=int(dev.get("ssh_port") or 22),
              username=dev.get("ssh_user") or "root", timeout=15,
              banner_timeout=20, auth_timeout=20,
              allow_agent=False, look_for_keys=False)
    if dev.get("key_path"):
        kw["key_filename"] = dev["key_path"]
    elif dev.get("ssh_password"):
        kw["password"] = dev["ssh_password"]
    else:
        kw["key_filename"] = ensure_server_key()
    try:
        c.connect(**kw)
    except SSHAuthError as e:
        if dev.get("ssh_password"):
            raise RuntimeError(f"SSH authentication failed for {dev.get('ssh_user')}@{dev['host']} "
                               f"— check the password") from e
        raise RuntimeError(f"SSH key rejected by {dev['host']} — set a password on the device "
                           f"or install our key first (Push SSH key)") from e
    except _socket.timeout as e:
        raise RuntimeError(f"SSH connect to {dev['host']}:{kw['port']} timed out — is the device up?") from e
    except _socket.gaierror as e:
        raise RuntimeError(f"SSH: cannot resolve host {dev['host']}") from e
    except _socket.error as e:
        raise RuntimeError(f"SSH connect to {dev['host']}:{kw['port']} failed — check the address/port: {e}") from e
    return c


def _exec_capture(client, cmd, timeout=300):
    """Run cmd on an open client, draining stdout+stderr in parallel (no pipe deadlock).
    Returns (stdout, stderr, exit_status)."""
    chan = client.get_transport().open_session()
    chan.exec_command(cmd)
    out_q, err_q = [], []

    def drain(f, q):
        try:
            while True:
                b = f.read(65536)
                if not b:
                    break
                q.append(b)
        except Exception:
            pass

    t1 = threading.Thread(target=drain, args=(chan.makefile("rb"), out_q), daemon=True)
    t2 = threading.Thread(target=drain, args=(chan.makefile_stderr("rb"), err_q), daemon=True)
    t1.start()
    t2.start()
    t1.join(timeout)
    t2.join(timeout)
    try:
        status = chan.recv_exit_status()
    except Exception:
        status = -1
    chan.close()
    return b"".join(out_q).decode(errors="replace"), b"".join(err_q).decode(errors="replace"), status


def _build_status(dev, backend, s):
    st = {"backend": backend, "online": True, "host": dev["host"], "name": dev["name"]}
    st["firmware"] = s.get("release", "")
    st["model"] = s.get("model", "")
    st["device_date"] = s.get("date", "")
    st["uptime_s"] = int(s.get("uptime") or 0)
    st["load"] = s.get("load", "").split()
    mem = dict(re.findall(r'(\w+)=(\d+)', s.get("mem", "")))
    st["mem_total_kb"] = int(mem.get("MemTotal", 0))
    st["mem_free_kb"] = int(mem.get("MemFree", 0))
    st["disk"] = s.get("disk", "")
    st["clients"] = int(s.get("clients") or 0)
    wan = s.get("wan", "")
    st["wan_up"] = '"up":true' in wan or '"up": true' in wan
    m = re.search(r'"ipaddr":\s*\[\s*"([^"]+)"', wan)
    st["wan_ip"] = m.group(1) if m else ""
    st.update({("fw_" + k): v for k, v in dict(re.findall(r'(in|fwd|out)=(\S+)', s.get("fw", ""))).items()})
    dbv = dict(re.findall(r'(pwauth|port)=(\S+)', s.get("dropbear", "")))
    st["dropbear_pwauth"] = dbv.get("pwauth", "")
    st["listeners"] = [int(x) for x in s.get("listeners", "").split()]
    st["telnet_on"] = 23 in st["listeners"]
    st["ntp"] = s.get("ntp", "")
    reds = []
    for line in s.get("redirects", "").splitlines():
        p = line.split()
        if len(p) >= 3:
            reds.append({"name": p[1], "dest_port": p[2]})
    st["redirects"] = reds
    upg = []
    for line in s.get("upgradable", "").splitlines():
        p = line.split()
        if len(p) >= 3:
            upg.append({"pkg": p[0], "installed": p[1], "available": p[2]})
    st["upgradable"] = upg
    return st


def ssh_gather(dev):
    c = _ssh_connect(dev)
    try:
        raw, err, status = _exec_capture(c, GATHER_SCRIPT, timeout=180)
    finally:
        c.close()
    if "##end##" not in raw:
        tail = (err.strip() or raw.strip())[-400:]
        raise RuntimeError(f"gather script did not complete on device (exit={status}); tail: {tail}")
    return _build_status(dev, "ssh", _parse_sections(raw))


# ------------------------------------------------------ OpenWrt: LuCI backend
_LUCI_SCHEMES = {}


def _luci_schemes(host):
    """Which LuCI scheme(s) to try for a host: probe 443 then 80, cache the result."""
    if host in _LUCI_SCHEMES:
        return _LUCI_SCHEMES[host]
    open_schemes = []
    for scheme, port in (("https", 443), ("http", 80)):
        try:
            with socket.create_connection((host, port), timeout=3):
                open_schemes.append(scheme)
        except Exception:
            pass
    _LUCI_SCHEMES[host] = open_schemes or ["https", "http"]
    return _LUCI_SCHEMES[host]


def _luci_rpc(dev, method, obj=None, args=None):
    """Call a LuCI RPC method. NOTE: the endpoint is /rpc (NOT /cgi-bin/luci/rpc)."""
    user = dev.get("luci_user") or "root"
    pw = dev.get("luci_pass") or ""
    port = dev.get("luci_port")
    base = f"{dev['host']}:{port}" if port else dev["host"]
    body = json.dumps({"method": "call", "params": ["luci.rpc", method, obj or "", args or []],
                       "id": 1}).encode()
    auth = "Basic " + base64.b64encode(f"{user}:{pw}".encode()).decode()
    last = None
    for scheme in _luci_schemes(base):
        req = urllib.request.Request(
            f"{scheme}://{base}/rpc", data=body, method="POST",
            headers={"Content-Type": "application/json", "Authorization": auth})
        try:
            if scheme == "https":
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                r = urllib.request.urlopen(req, timeout=15, context=ctx)
            else:
                r = urllib.request.urlopen(req, timeout=15)
            with r:
                data = json.loads(r.read().decode())
            if data.get("error"):
                raise RuntimeError(f"LuCI rpc {method}: {data['error']}")
            return data.get("payload")
        except Exception as e:
            last = e
    raise last or RuntimeError("LuCI unreachable")


def luci_gather(dev):
    st = {"backend": "luci", "online": True, "host": dev["host"], "name": dev["name"]}
    try:
        si = _luci_rpc(dev, "luci.sys.sysinfo") or {}
        st["model"] = si.get("model", "")
        st["firmware"] = f"OpenWrt {si.get('firmware', '')}"
        st["hostname"] = si.get("hostname", "")
    except Exception as e:
        raise RuntimeError(f"LuCI sysinfo failed: {e}")
    try:
        stt = _luci_rpc(dev, "luci.sys.status") or {}
        st["uptime_s"] = int(stt.get("uptime") or 0)
        st["load"] = (stt.get("load") or "").split()
        mem = stt.get("mem") or {}
        st["mem_total_kb"] = int(mem.get("total") or 0)
        st["mem_free_kb"] = int(mem.get("free") or 0)
        wan = (stt.get("net") or {}).get("wan") or {}
        st["wan_up"] = bool(wan.get("up"))
        v4 = wan.get("ipv4") or []
        st["wan_ip"] = (v4[0].get("address", "") if v4 else "")
    except Exception:
        pass
    try:
        st["clients"] = int((_luci_rpc(dev, "luci.devices") or {}).get("clients") or 0)
    except Exception:
        st["clients"] = None
    try:
        su = _luci_rpc(dev, "luci.sys.sysupgrade") or {}
        st["sysupgrade_available"] = bool(su.get("available"))
        st["latest"] = su.get("latest_version", "")
    except Exception:
        st["sysupgrade_available"] = None
    try:
        st["upgradable"] = [
            {"pkg": p.get("pkg"), "installed": p.get("installed"), "available": p.get("available")}
            for p in (_luci_rpc(dev, "luci.opkg.upgradable") or []) if isinstance(p, dict)
        ]
    except Exception:
        st["upgradable"] = []
    st["telnet_on"] = None
    st["ntp"] = ""
    st["listeners"] = []
    st["device_date"] = ""
    try:
        cfg = _luci_rpc(dev, "luci.config.get", "firewall", []) or {}
        fw = cfg.get("firewall", cfg) if isinstance(cfg, dict) else {}
        d = fw.get("defaults") if isinstance(fw, dict) else None
        d = d[0] if isinstance(d, list) and d else (d if isinstance(d, dict) else {})
        st["fw_in"] = d.get("input", "")
        st["fw_fwd"] = d.get("forward", "")
        st["fw_out"] = d.get("output", "")
        r = (fw or {}).get("redirect") or []
        if isinstance(r, dict):
            r = [r]
        reds = []
        for i, rr in enumerate(r):
            if isinstance(rr, dict) and rr.get("dest_port"):
                reds.append({"name": rr.get("name") or f"redirect[{i}]", "dest_port": rr.get("dest_port")})
        st["redirects"] = reds
    except Exception:
        st["fw_in"] = ""
        st["redirects"] = []
    return st


def gather(dev):
    if dev["access"] == "ssh":
        return ssh_gather(dev)
    if dev["access"] == "luci":
        return luci_gather(dev)
    raise RuntimeError("device has no management access configured")


# ------------------------------------------------------------------ audit
def audit_status(st):
    f = []

    def add(rule, sev, msg, detail="", rec=""):
        f.append({"rule_id": rule, "severity": sev, "message": msg, "detail": detail, "rec": rec})

    if st.get("telnet_on"):
        add("telnet", "HIGH", "Telnet (port 23) is listening",
            "Cleartext service exposed", "Disable telnet; use SSH with key auth")
    if str(st.get("dropbear_pwauth", "")).lower() in ("yes", "true", "on", "1"):
        add("ssh_password_auth", "MEDIUM", "SSH allows password authentication",
            "dropbear PasswordAuth=" + str(st.get("dropbear_pwauth", "")),
            "Set PasswordAuth='no' and use SSH keys")
    if st.get("fw_in") == "ACCEPT":
        add("fw_input_accept", "HIGH", "Firewall default INPUT policy is ACCEPT",
            "All inbound traffic to the router is allowed by default",
            "Set firewall defaults input=DROP (standard OpenWrt default)")
    if st.get("fw_fwd") == "ACCEPT":
        add("fw_forward_accept", "HIGH", "Firewall default FORWARD policy is ACCEPT",
            "All inter-zone forwarding allowed by default",
            "Set forward=DROP and allow only intended traffic")
    if st.get("ntp") in ("false", "0", "disabled"):
        add("ntp_disabled", "LOW", "NTP time sync is disabled",
            "", "Enable system.ntp so logs and certs stay correct")
    if st.get("upgradable"):
        pkgs = ", ".join(p.get("pkg", "?") for p in st["upgradable"][:8])
        add("outdated_packages", "MEDIUM", f"{len(st['upgradable'])} package(s) have updates",
            pkgs, "Review in the Updates tab and apply")
    if st.get("sysupgrade_available"):
        add("fw_update", "MEDIUM", "Firmware (sysupgrade) update available",
            st.get("latest", ""), "Back up config, then upgrade")
    if st.get("wan_up") is False:
        add("wan_down", "INFO", "WAN interface reports down",
            st.get("wan_ip", ""), "Check upstream link if unexpected")
    if st.get("redirects"):
        rs = ", ".join(f"{r['name']}->{r['dest_port']}" for r in st["redirects"][:8])
        add("wan_forwards", "INFO", f"{len(st['redirects'])} WAN port forward(s)",
            rs, "Confirm each forward is intended")
    if st.get("device_date"):
        try:
            dev_t = datetime.strptime(st["device_date"], "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
            drift = abs((datetime.now(timezone.utc) - dev_t).total_seconds())
            if drift > 600:
                add("clock_drift", "LOW", f"Device clock off by ~{int(drift // 60)} min",
                    st["device_date"], "Enable NTP")
        except Exception:
            pass
    return f


def apply_findings(dev, st):
    findings = audit_status(st)
    current = {r["rule_id"] for r in q("SELECT * FROM active_findings WHERE device_id=?", (dev["id"],))}
    new_rules = {f["rule_id"]: f for f in findings}
    fired = []
    for rule, f in new_rules.items():
        if rule not in current:
            execute("INSERT OR REPLACE INTO active_findings(device_id, rule_id, severity, message, detail, rec, ts) "
                    "VALUES(?,?,?,?,?,?,?)", (dev["id"], rule, f["severity"], f["message"], f["detail"], f["rec"], now()))
            execute("INSERT INTO findings(ts, device_id, device_name, rule_id, severity, message, detail, rec) "
                    "VALUES(?,?,?,?,?,?,?,?)", (now(), dev["id"], dev["name"], rule, f["severity"],
                                                f["message"], f["detail"], f["rec"]))
            fired.append(f)
        else:
            execute("UPDATE active_findings SET severity=?, message=?, detail=?, rec=?, ts=? "
                    "WHERE device_id=? AND rule_id=?",
                    (f["severity"], f["message"], f["detail"], f["rec"], now(), dev["id"], rule))
    for rule in list(current - set(new_rules)):
        execute("DELETE FROM active_findings WHERE device_id=? AND rule_id=?", (dev["id"], rule))
    for f in fired:
        try:
            fire_alert(dev, f)
        except Exception:
            pass
    return findings


# --------------------------------------------------------------- alerting
DEFAULT_ALERTS = {
    "min_severity": "MEDIUM",
    "channels": {
        "dashboard": True,
        "email": {"enabled": False, "smtp_host": "", "smtp_port": 587, "use_tls": True,
                  "user": "", "password": "", "from": "", "to": ""},
        "telegram": {"enabled": False, "token": "", "chat_id": ""},
        "webhook": {"enabled": False, "url": ""},
    },
}


def get_alert_cfg():
    raw = get_setting("alerts", "")
    merged = json.loads(json.dumps(DEFAULT_ALERTS))
    if not raw:
        return merged
    try:
        c = json.loads(raw)
        for k in merged:
            if k in c:
                if isinstance(merged[k], dict) and isinstance(c[k], dict):
                    merged[k].update(c[k])
                else:
                    merged[k] = c[k]
        return merged
    except Exception:
        return merged


def set_alert_cfg(cfg):
    set_setting("alerts", json.dumps(cfg))


def fire_alert(dev, finding):
    cfg = get_alert_cfg()
    min_rank = SEV_RANK.get(cfg.get("min_severity", "MEDIUM"), 2)
    text = f"[{finding['severity']}] {dev['name']} ({dev['host']}): {finding['message']}"
    log_id = execute("INSERT INTO alert_log(ts, device, severity, rule_id, message, channels) "
                     "VALUES(?,?,?,?,?,?)", (now(), dev["name"], finding["severity"],
                                             finding["rule_id"], finding["message"], ""))
    used = []
    if SEV_RANK.get(finding["severity"], 0) < min_rank:
        return used
    ch = cfg.get("channels", {})
    if ch.get("dashboard"):
        used.append("dashboard")
    em = ch.get("email") or {}
    if em.get("enabled") and em.get("to") and em.get("smtp_host"):
        try:
            msg = EmailMessage()
            msg["Subject"] = "OpenWrt alert"
            msg["From"] = em.get("from") or em.get("user") or "owctl@lan"
            msg["To"] = em["to"]
            body = text
            if finding.get("rec"):
                body += f"\n\nSuggestion: {finding['rec']}"
            msg.set_content(body)
            with smtplib.SMTP(em["smtp_host"], int(em.get("smtp_port") or 587), timeout=20) as s:
                if em.get("use_tls", True):
                    s.starttls()
                if em.get("user"):
                    s.login(em["user"], em.get("password", ""))
                s.send_message(msg)
            used.append("email")
        except Exception as e:
            used.append(f"email:FAIL({e})")
    tg = ch.get("telegram") or {}
    if tg.get("enabled") and tg.get("token") and tg.get("chat_id"):
        try:
            payload = json.dumps({"chat_id": tg["chat_id"], "text": text}).encode()
            req = urllib.request.Request(
                f"https://api.telegram.org/bot{tg['token']}/sendMessage", data=payload,
                headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=20) as r:
                r.read()
            used.append("telegram")
        except Exception as e:
            used.append(f"telegram:FAIL({e})")
    wh = ch.get("webhook") or {}
    if wh.get("enabled") and wh.get("url"):
        try:
            payload = json.dumps({"ts": now(), "device": dev["name"], "host": dev["host"], **finding}).encode()
            req = urllib.request.Request(wh["url"], data=payload,
                                         headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=20) as r:
                r.read()
            used.append("webhook")
        except Exception as e:
            used.append(f"webhook:FAIL({e})")
    if used:
        execute("UPDATE alert_log SET channels=? WHERE id=?", (",".join(used), log_id))
    return used


# ------------------------------------------------------------------ sweep
def parse_spec(spec):
    import ipaddress
    ips = []
    for part in re.split(r"[,\s]+", (spec or "").strip()):
        if not part:
            continue
        if "/" in part:
            for ip in ipaddress.ip_network(part, strict=False):
                if not ip.is_loopback:
                    ips.append(str(ip))
        elif re.fullmatch(r"[\d.]+-[\d.]+", part):
            a, b = part.split("-")
            a4, b4 = a.split("."), b.split(".")
            if len(a4) == len(b4) == 4 and a4[:3] == b4[:3]:
                for i in range(int(a4[3]), int(b4[3]) + 1):
                    ips.append(f"{a4[0]}.{a4[1]}.{a4[2]}.{i}")
        elif re.fullmatch(r"[\d.]+", part):
            ips.append(part)
    seen, out = set(), []
    for ip in ips:
        if ip not in seen:
            seen.add(ip)
            out.append(ip)
    return out[:4096]


def _probe(ip):
    res = {"host": ip, "ports": [], "hints": [], "likely_openwrt": False}
    for p in (22, 80, 443, 8080):
        try:
            with socket.create_connection((ip, p), timeout=1.0):
                res["ports"].append(p)
        except Exception:
            pass
    if 22 in res["ports"]:
        try:
            s = socket.create_connection((ip, 22), timeout=2)
            s.settimeout(2)
            banner = s.recv(120).decode(errors="replace").strip()
            s.close()
            res["hints"].append("ssh:" + (banner or "?"))
            if "openwrt" in banner.lower():
                res["likely_openwrt"] = True
        except Exception:
            pass
    http_port = 80 if 80 in res["ports"] else (443 if 443 in res["ports"] else None)
    if http_port:
        try:
            scheme = "http" if http_port == 80 else "https"
            req = urllib.request.Request(f"{scheme}://{ip}/", headers={"User-Agent": "owctl-sweep"})
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with urllib.request.urlopen(req, timeout=3, context=ctx) as r:
                head = r.read(1024).decode(errors="replace").lower()
                res["hints"].append("http:" + (r.headers.get("Server") or "no-server-header"))
                if "luci" in head or "openwrt" in head:
                    res["likely_openwrt"] = True
        except Exception:
            pass
    return res


def run_sweep(spec):
    ips = parse_spec(spec)
    if not ips:
        raise RuntimeError("no valid addresses in sweep spec (try 192.168.1.0/24 or 192.168.1.1-192.168.1.250)")
    out = []
    with ThreadPoolExecutor(max_workers=64) as ex:
        futs = {ex.submit(_probe, ip): ip for ip in ips}
        for fu in as_completed(futs, timeout=max(60, len(ips))):
            try:
                r = fu.result(timeout=15)
                if r["ports"]:
                    out.append(r)
            except Exception:
                pass
    try:
        import ipaddress
        out.sort(key=lambda x: int(ipaddress.ip_address(x["host"])))
    except Exception:
        pass
    return {"requested": len(ips), "found": len(out),
            "openwrt": [c["host"] for c in out if c["likely_openwrt"]],
            "candidates": out}


# -------------------------------------------------------------- operations
def ensure_server_key():
    """Server-side SSH keypair used for key auth to devices (created on demand)."""
    path = os.path.join(DATA_DIR, "ssh_key")
    if not os.path.exists(path):
        import paramiko
        paramiko.RSAKey.generate(3072).write_private_key_file(path)
    return path


def _key_pub_line():
    import paramiko
    k = paramiko.RSAKey.from_private_key_file(ensure_server_key())
    return f"{k.get_name()} {k.get_base64()} owctl"


def ssh_test(dev):
    """Verify we can reach + authenticate to the device and read a banner."""
    try:
        c = _ssh_connect(dev)
    except Exception as e:
        return {"ok": False, "detail": str(e)}
    try:
        out, err, status = _exec_capture(
            c, "cat /etc/openwrt_release 2>/dev/null | head -1; uptime", timeout=30)
        return {"ok": True, "detail": (out.strip() or err.strip() or "connected")[:200]}
    except Exception as e:
        return {"ok": False, "detail": str(e)}
    finally:
        c.close()


def luci_test(dev):
    try:
        si = _luci_rpc(dev, "luci.sys.sysinfo") or {}
        detail = f"{si.get('model', '')} {si.get('firmware', '')}".strip()
        return {"ok": True, "detail": (detail or "connected")[:200]}
    except Exception as e:
        return {"ok": False, "detail": str(e)}


def push_ssh_key(dev):
    """Install the owctl public key on the device, then verify key-only auth."""
    pub = _key_pub_line()
    key_path = ensure_server_key()
    c = _ssh_connect(dev)
    try:
        sftp = c.open_sftp()
        try:
            sftp.mkdir("/home/root/.ssh")
        except IOError:
            pass
        sftp.chmod("/home/root/.ssh", 0o700)
        existing = ""
        try:
            with sftp.open("/home/root/.ssh/authorized_keys", "r") as fh:
                existing = fh.read().decode(errors="replace")
        except IOError:
            pass
        if pub not in existing.splitlines():
            with sftp.open("/home/root/.ssh/authorized_keys", "a") as fh:
                fh.write(pub + "\n")
        sftp.chmod("/home/root/.ssh/authorized_keys", 0o600)
        sftp.close()
    finally:
        c.close()
    execute("UPDATE devices SET key_path=? WHERE id=?", (key_path, dev["id"]))
    probe = dict(dev)
    probe["key_path"] = key_path
    probe["ssh_password"] = ""
    vt = ssh_test(probe)
    return {"ok": vt["ok"], "public_key": pub, "detail": vt["detail"], "key_saved": True}


def do_backup(dev):
    ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    slug = re.sub(r"\W+", "_", dev["name"])
    if dev["access"] == "ssh":
        c = _ssh_connect(dev)
        try:
            remote = f"/tmp/owctl-backup-{ts}.conf"
            out, err, status = _exec_capture(c, f"uci export > {remote} && echo BACKUP_OK", timeout=120)
            if status != 0 or "BACKUP_OK" not in out:
                raise RuntimeError(f"uci export failed on device (exit={status}): {(err or out).strip()[:300]}")
            local = os.path.join(BACKUP_DIR, f"{slug}-{ts}.conf")
            sftp = c.open_sftp()
            try:
                sftp.get(remote, local)
            finally:
                sftp.close()
            c.exec_command(f"rm -f {remote}")
            kind = "uci-export"
        finally:
            c.close()
    elif dev["access"] == "luci":
        cfg = _luci_rpc(dev, "luci.config.get", "", [])
        local = os.path.join(BACKUP_DIR, f"{slug}-{ts}.json")
        with open(local, "w") as fh:
            json.dump(cfg, fh, indent=2)
        kind = "luci-config"
    else:
        raise HTTPException(400, "device has no management access configured")
    size = os.path.getsize(local)
    execute("INSERT INTO backups(ts, device_id, device_name, kind, path, size) VALUES(?,?,?,?,?,?)",
            (now(), dev["id"], dev["name"], kind, local, size))
    return local


def do_upgrade(dev, packages):
    if dev["access"] != "ssh":
        raise HTTPException(400, "package upgrades require SSH access on this device")
    c = _ssh_connect(dev)
    try:
        if not packages:
            cmd = "opkg update && opkg upgrade -y"
        else:
            safe = [p for p in packages if re.fullmatch(r"[A-Za-z0-9_.+-]+", p)]
            if len(safe) != len(packages):
                raise HTTPException(400, "invalid package name in list")
            cmd = "opkg update && opkg upgrade -y " + " ".join(safe)
        out, err, status = _exec_capture(c, cmd, timeout=3600)
        result = (out.strip() + "\n--- stderr ---\n" + err.strip()).strip()
        if status != 0:
            raise RuntimeError(f"upgrade exited with status {status}")
    finally:
        c.close()
    return result[:30000]


def do_reboot(dev):
    if dev["access"] != "ssh":
        raise HTTPException(400, "reboot requires SSH access on this device")
    c = _ssh_connect(dev)
    try:
        c.exec_command("reboot")
    finally:
        c.close()
    return "reboot sent"


def check_device(dev):
    st = gather(dev)
    execute("UPDATE devices SET status='online', last_checked=? WHERE id=?", (now(), dev["id"]))
    findings = apply_findings(dev, st)
    return {"status": st, "findings": findings}


# --------------------------------------------------------------- scheduler
def _scheduler():
    while True:
        try:
            interval_min = max(5, int(get_setting("audit_interval_min", "30") or 30))
        except Exception:
            interval_min = 30
        for _ in range(interval_min * 12):
            time.sleep(5)
        for dev in q("SELECT * FROM devices WHERE access IN ('ssh','luci')"):
            try:
                st = gather(dev)
                execute("UPDATE devices SET status='online', last_checked=? WHERE id=?", (now(), dev["id"]))
                apply_findings(dev, st)
            except Exception:
                execute("UPDATE devices SET status='offline' WHERE id=?", (dev["id"],))


# --------------------------------------------------------------------- app
app = FastAPI(title="owctl")
init_db()


@app.middleware("http")
async def token_guard(request, call_next):
    t = get_setting("ui_token", "") or os.environ.get("OWCTL_TOKEN", "")
    if t and request.url.path.startswith("/api/"):
        auth = request.headers.get("authorization", "")
        if auth != f"Bearer {t}" and request.query_params.get("token", "") != t:
            return JSONResponse({"error": "unauthorized"}, status_code=401)
    return await call_next(request)


@app.get("/")
def index():
    return FileResponse(os.path.join(BASE, "static", "index.html"))


@app.get("/api/devices")
def list_devices():
    return q("SELECT * FROM devices ORDER BY id")


@app.post("/api/devices")
async def add_device(request: Request):
    d = await request.json()
    host = (d.get("host") or "").strip()
    if not re.fullmatch(r"[\d.]+", host):
        raise HTTPException(400, "host must be an IPv4 address")
    name = (d.get("name") or host).strip()
    try:
        did = execute(
            "INSERT INTO devices(name,host,role,access,ssh_port,ssh_user,ssh_password,key_path,"
            "luci_user,luci_pass,luci_port,added_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
            (name, host, d.get("role") or "router", d.get("access") or "ssh",
             int(d.get("ssh_port") or 22), d.get("ssh_user") or "root",
             d.get("ssh_password") or "", d.get("key_path") or "",
             d.get("luci_user") or "root", d.get("luci_pass") or "",
             (int(d["luci_port"]) if d.get("luci_port") else None), now()))
    except sqlite3.IntegrityError:
        raise HTTPException(400, f"host {host} already registered")
    return {"id": did}


@app.put("/api/devices/{did}")
async def update_device(request: Request, did: int):
    d = await request.json()
    cur = q("SELECT * FROM devices WHERE id=?", (did,))
    if not cur:
        raise HTTPException(404, "device not found")
    dev = cur[0]
    def g(k, dflt=None):
        return d.get(k) if d.get(k) is not None else dflt
    execute("UPDATE devices SET name=?, role=?, access=?, ssh_port=?, ssh_user=?, ssh_password=?, "
            "key_path=?, luci_user=?, luci_pass=?, luci_port=? WHERE id=?",
            (g("name", dev["name"]), g("role", dev["role"]), g("access", dev["access"]),
             int(g("ssh_port", dev["ssh_port"] or 22)), g("ssh_user", dev["ssh_user"]),
             g("ssh_password", dev["ssh_password"]), g("key_path", dev["key_path"]),
             g("luci_user", dev["luci_user"]), g("luci_pass", dev["luci_pass"]),
             (int(g("luci_port", dev.get("luci_port") or 0)) or None), did))
    return {"ok": True}


@app.delete("/api/devices/{did}")
def delete_device(did: int):
    execute("DELETE FROM active_findings WHERE device_id=?", (did,))
    execute("DELETE FROM devices WHERE id=?", (did,))
    return {"ok": True}


@app.post("/api/devices/{did}/check")
def device_check(did: int):
    cur = q("SELECT * FROM devices WHERE id=?", (did,))
    if not cur:
        raise HTTPException(404, "device not found")
    try:
        return check_device(cur[0])
    except Exception as e:
        execute("UPDATE devices SET status='offline' WHERE id=?", (did,))
        raise HTTPException(502, f"device check failed: {e}")


@app.post("/api/devices/{did}/test")
def device_test(did: int):
    cur = q("SELECT * FROM devices WHERE id=?", (did,))
    if not cur:
        raise HTTPException(404, "device not found")
    dev = cur[0]
    if dev["access"] == "ssh":
        return ssh_test(dev)
    if dev["access"] == "luci":
        return luci_test(dev)
    return {"ok": False, "detail": "device has no management access configured"}


@app.post("/api/devices/{did}/push-key")
def device_push_key(did: int):
    cur = q("SELECT * FROM devices WHERE id=?", (did,))
    if not cur:
        raise HTTPException(404, "device not found")
    if cur[0]["access"] != "ssh":
        raise HTTPException(400, "push-key requires ssh access")
    try:
        return push_ssh_key(cur[0])
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(502, f"key push failed: {e}")


@app.post("/api/devices/{did}/backup")
def device_backup(did: int):
    cur = q("SELECT * FROM devices WHERE id=?", (did,))
    if not cur:
        raise HTTPException(404, "device not found")
    try:
        return {"backup": do_backup(cur[0])}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(502, f"backup failed: {e}")


@app.post("/api/devices/{did}/upgrade")
async def device_upgrade(request: Request, did: int):
    cur = q("SELECT * FROM devices WHERE id=?", (did,))
    if not cur:
        raise HTTPException(404, "device not found")
    d = await request.json()
    pkgs = d.get("packages") or []
    try:
        return {"output": do_upgrade(cur[0], pkgs)}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(502, f"upgrade failed: {e}")


@app.post("/api/devices/{did}/reboot")
def device_reboot(did: int):
    cur = q("SELECT * FROM devices WHERE id=?", (did,))
    if not cur:
        raise HTTPException(404, "device not found")
    try:
        return do_reboot(cur[0])
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(502, f"reboot failed: {e}")


@app.post("/api/sweep")
async def sweep(request: Request):
    d = await request.json()
    try:
        return run_sweep(d.get("spec", ""))
    except RuntimeError as e:
        raise HTTPException(400, str(e))


@app.get("/api/findings")
def findings():
    return {"active": q("SELECT * FROM active_findings ORDER BY ts DESC"),
            "history": q("SELECT * FROM findings ORDER BY id DESC LIMIT 200")}


@app.post("/api/findings/ack")
async def ack_finding(request: Request):
    d = await request.json()
    did, rule = int(d["device_id"]), d["rule_id"]
    execute("UPDATE active_findings SET severity='INFO' WHERE device_id=? AND rule_id=?", (did, rule))
    return {"ok": True}


@app.get("/api/alerts/config")
def alerts_get():
    return get_alert_cfg()


@app.put("/api/alerts/config")
async def alerts_put(request: Request):
    set_alert_cfg(await request.json())
    return {"ok": True}


@app.get("/api/alerts/log")
def alerts_log():
    return q("SELECT * FROM alert_log ORDER BY id DESC LIMIT 200")


@app.get("/api/backups")
def backups():
    return q("SELECT * FROM backups ORDER BY id DESC LIMIT 100")


@app.get("/api/settings")
def settings_get():
    return {"audit_interval_min": get_setting("audit_interval_min", "30"),
            "ui_token_set": bool(get_setting("ui_token", ""))}


@app.put("/api/settings")
async def settings_put(request: Request):
    d = await request.json()
    if "audit_interval_min" in d:
        set_setting("audit_interval_min", str(int(d["audit_interval_min"])))
    if "ui_token" in d:
        set_setting("ui_token", d["ui_token"] or "")
    return {"ok": True}


app.mount("/static", StaticFiles(directory=os.path.join(BASE, "static")), name="static")


if __name__ == "__main__":
    import uvicorn
    threading.Thread(target=_scheduler, daemon=True).start()
    print(f"owctl: http://{HOST}:{PORT}")
    uvicorn.run(app, host=HOST, port=PORT, log_level="warning")
