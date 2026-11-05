"""owctl.routes"""
import owctl  # shared namespace (patched names)

import base64, difflib, json, os, re, secrets, smtplib, socket, sqlite3, ssl
import threading, time, logging, sys, ipaddress, paramiko, bcrypt
import urllib.parse, urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from email.message import EmailMessage
from fastapi import FastAPI, HTTPException, Request
from starlette.concurrency import run_in_threadpool
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

@owctl.app.get("/api/health")
def api_health():
    """Liveness probe for supervisors (launchd/systemd/curl) and the dashboard.
    Deliberately public: it exposes no state, only that the process is up and
    can open the DB. Keep it outside the auth guard's 401 paths."""
    try:
        ok = bool(owctl.q("SELECT 1"))
    except Exception:
        ok = False
    return {"ok": ok, "uptime_s": int(time.time() - owctl.SERVER_STARTED_AT)}


@owctl.app.post("/api/devices/{did}/pending-apply")
async def pending_apply(request: Request, did: int):
    """Apply (restart the daemons for) this device's saved-but-not-applied
    config changes — the LuCI 'Save & Apply' half, run on demand."""
    dev = _require_device(did)
    return owctl.apply_pending_for(dev)


@owctl.app.get("/api/devices/{did}/pending-applies")
def pending_applies_list(did: int):
    """List the config features Saved (committed) but not yet applied on a device."""
    dev = _require_device(did)
    features = owctl.pending_apply_for(dev)
    return {"device": dev["name"], "features": features, "count": len(features)}


@owctl.app.get("/api/pending")
def pending_all():
    """Network-wide view: every device's saved-but-not-applied config features,
    so 'the one device' shows what's pending across the whole network and where."""
    out = []
    for dev in owctl.q("SELECT * FROM devices ORDER BY id"):
        feats = owctl.pending_apply_for(dev)
        if feats:
            out.append({"device_id": dev["id"], "name": dev["name"], "host": dev["host"],
                        "access": dev["access"],
                        "features": [f["feature"] for f in feats],
                        "saved_at": max(f["saved_at"] for f in feats if f.get("saved_at"))})
    total = sum(len(x["features"]) for x in out)
    return {"count": total,
            "devices": len(out),
            "features": sorted({f for x in out for f in x["features"]}),
            "items": out}


@owctl.app.post("/api/pending/apply")
async def pending_apply_all(request: Request):
    """Apply (restart the daemons for) every device's pending changes. Optionally
    scope with {devices: [id,...]}; without it, all devices. Per-device results
    are reported; one device's SSH failure does not abort the rest."""
    try:
        d = await request.json()
    except Exception:
        d = {}
    scope = d.get("devices")
    devs = owctl.q("SELECT * FROM devices ORDER BY id")
    if scope:
        scope = {int(x) for x in scope}
        devs = [x for x in devs if x["id"] in scope]
    results = []
    for dev in devs:
        if not owctl.pending_apply_for(dev):
            continue  # nothing pending on this device
        try:
            results.append(owctl.apply_pending_for(dev))
        except Exception as e:
            results.append({"device": dev["name"], "ok": False, "error": str(e)})
    ok = sum(1 for r in results if r.get("ok"))
    return {"applied": ok, "failed": len(results) - ok, "results": results}


def compare_device_drift(rows, fields):
    """Pure: which fields diverge across a set of devices.

    rows: [{name, host, values:{field: value_or_None}}] (already-normalized).
    fields: list of field names to compare. Returns {field: {status,
    distinct:[{name,value}], uniform_value?}} where status is 'drift'
    (>=2 distinct non-null values), 'missing' (some null, some set) or
    'ok' (uniform). Fields that are null on every device are omitted.
    """
    out = {}
    for f in fields:
        vals = [(r.get("name"), r.get("values", {}).get(f)) for r in rows]
        nonnull = [v for _, v in vals if v not in (None, "")]
        if not nonnull:
            continue
        distinct = {}
        for name, v in vals:
            if v in (None, ""):
                continue
            distinct.setdefault(v, []).append(name)
        if len(distinct) > 1:
            out[f] = {"status": "drift",
                      "distinct": [{"value": v, "devices": ns} for v, ns in distinct.items()]}
        else:
            the_v = next(iter(distinct.keys()))
            missing = [n for n, v in vals if v in (None, "")]
            out[f] = {"status": "missing" if missing else "ok",
                      "uniform_value": the_v, "missing_on": missing}
    return out


@owctl.app.get("/api/drift")
def drift_report():
    """Cross-device consistency report: compare firmware, key package
    versions and DHCP/QoS settings across every device (from the last
    status snapshot). The 'one network' view of where boxes have diverged."""
    rows = []
    for dev in owctl.q("SELECT * FROM devices ORDER BY id"):
        st = owctl.q("SELECT * FROM device_status WHERE device_id=? LIMIT 1", (dev["id"],))
        if not st:
            continue
        st = st[0]
        pkgs = []
        try:
            pkgs = json.loads(st["installed_pkgs"]) if st["installed_pkgs"] else []
        except Exception:
            pkgs = []
        def _ver(name):
            for p in pkgs:
                if isinstance(p, dict) and p.get("pkg") == name:
                    return p.get("version")
            return None
        rows.append({
            "name": dev["name"], "host": dev["host"], "online": dev["status"] == "online",
            "values": {
                "firmware": st.get("firmware"),
                "dnsmasq": _ver("dnsmasq"),
                "odhcpd": _ver("odhcpd"),
                "openwrt": _ver("openwrt"),
            },
            "snapshot_at": st.get("ts"),
        })
    if len(rows) < 2:
        return {"count": 0, "devices": len(rows), "drift": {},
                "note": "need at least 2 devices with status snapshots to compare"}
    fields = ["firmware", "dnsmasq", "odhcpd", "openwrt"]
    drift = compare_device_drift(rows, fields)
    divergent = [f for f, d in drift.items() if d.get("status") == "drift"]
    return {"count": len(divergent), "devices": len(rows), "drift": drift,
            "fields": fields, "divergent": divergent,
            "rows": [{k: r[k] for k in ("name", "host", "online", "snapshot_at")} |
                     {"values": r["values"]} for r in rows]}


def _ver_key(v):
    """Comparable numeric tuple from a package version string (best-effort).
    '2.90' -> (2, 90), '1:2.3' -> (1, 2, 3); non-numeric runs -> 0."""
    import re as _re
    out = []
    for tok in _re.split(r"[.:\-+~]", str(v)):
        out.append(int(tok) if tok.isdigit() else 0)
    return tuple(out)


@owctl.app.get("/api/rebaseline/preview")
def rebaseline_preview():
    """Which devices lag behind the fleet baseline and what the baseline is.
    Baseline = the most common firmware among snapshot-carrying devices and
    the latest known version of each compared package. Read-only (snapshots)."""
    fields = ["dnsmasq", "odhcpd", "openwrt"]
    rows = []
    for dev in owctl.q("SELECT * FROM devices ORDER BY id"):
        st = owctl.q("SELECT * FROM device_status WHERE device_id=? LIMIT 1", (dev["id"],))
        if not st:
            continue
        st = st[0]
        pkgs = []
        try:
            pkgs = json.loads(st["installed_pkgs"]) if st["installed_pkgs"] else []
        except Exception:
            pkgs = []
        def _ver(name):
            for p in pkgs:
                if isinstance(p, dict) and p.get("pkg") == name:
                    return p.get("version")
            return None
        rows.append({
            "device_id": dev["id"], "name": dev["name"], "host": dev["host"],
            "online": dev["status"] == "online",
            "firmware": st.get("firmware"),
            "versions": {f: _ver(f) for f in fields},
        })
    if len(rows) < 2:
        return {"baseline": {}, "baseline_firmware": None, "lagging": [],
                "device_count": len(rows),
                "note": "need at least 2 devices with status snapshots"}
    # Most common firmware (tie -> lexicographically latest).
    fw = {}
    for r in rows:
        if r["firmware"]:
            fw[r["firmware"]] = fw.get(r["firmware"], 0) + 1
    baseline_firmware = max(fw.items(), key=lambda kv: (kv[1], kv[0]))[0] if fw else None
    baseline = {}
    for f in fields:
        best = None
        for r in rows:
            v = r["versions"].get(f)
            if not v:
                continue
            if best is None or _ver_key(v) > _ver_key(best):
                best = v
        if best is not None:
            baseline[f] = best
    lagging = []
    for r in rows:
        diff = {}
        if r["firmware"] and baseline_firmware and r["firmware"] != baseline_firmware:
            diff["firmware"] = r["firmware"]
        for f in fields:
            bv = baseline.get(f)
            dv = r["versions"].get(f)
            if bv and (not dv or _ver_key(dv) < _ver_key(bv)):
                diff[f] = dv
        if diff:
            lagging.append({"device_id": r["device_id"], "name": r["name"],
                            "host": r["host"], "differs": diff})
    return {"baseline_firmware": baseline_firmware, "baseline": baseline,
            "lagging": lagging, "device_count": len(rows)}


@owctl.app.post("/api/rebaseline/apply")
async def rebaseline_apply(request: Request):
    """Re-baseline a scoped set of devices (default: every device): refresh
    feeds, upgrade the compared packages, optional sysupgrade. Per-device
    error isolation — one box failing never aborts the fleet. Long-running."""
    try:
        body = await request.json()
    except Exception:
        body = {}
    packages = body.get("packages") or ["dnsmasq", "odhcpd", "openwrt"]
    sysupgrade = bool(body.get("sysupgrade"))
    devices = body.get("devices") or [d["id"] for d in owctl.q("SELECT id FROM devices ORDER BY id")]
    results = []
    for did in devices:
        cur = owctl.q("SELECT * FROM devices WHERE id=?", (did,))
        if not cur:
            results.append({"device_id": did, "name": "?", "ok": False, "error": "unknown device"})
            continue
        dev = cur[0]
        try:
            out = await run_in_threadpool(owctl.do_rebaseline, dev, packages, sysupgrade=sysupgrade)
            results.append({"device_id": did, "name": dev["name"], "ok": True,
                            "output": out[-4000:]})
        except Exception as e:
            results.append({"device_id": did, "name": dev["name"], "ok": False, "error": str(e)})
    ok = sum(1 for r in results if r["ok"])
    return {"ok": ok, "failed": len(results) - ok, "results": results}


@owctl.app.get("/")
def index():
    return FileResponse(os.path.join(owctl.BASE, "static", "index.html"))


@owctl.app.get("/api/devices")
def list_devices():
    rows = owctl.q("""SELECT d.id, d.name, d.host, d.role, d.access, d.status,
                       d.health_score, d.last_checked, d.added_at, d.tags,
                       d.ssh_port, d.ssh_user, d.ssh_password, d.key_path,
                       d.luci_user, d.luci_pass, d.luci_port,
                       s.wifi_capable
                FROM devices d LEFT JOIN device_status s ON s.device_id = d.id
                ORDER BY d.id""")
    for r in rows:
        r["wifi_capable"] = bool(r["wifi_capable"]) if r["wifi_capable"] is not None else None
        # Security: never return device credentials to the client. Expose presence only.
        r["has_ssh_password"] = bool(r.get("ssh_password"))
        r["has_luci_pass"] = bool(r.get("luci_pass"))
        r["ssh_password"] = ""
        r["luci_pass"] = ""
    return rows


@owctl.app.get("/api/network")
def network_overview():
    """Read-only aggregate of the whole network: one row per registered device,
    totals, gateway, VLANs and recent offline events. No SSH. Instant.
    """
    rows = owctl.q("""SELECT d.id, d.name, d.host, d.role, d.access, d.status,
                      d.health_score, d.last_checked,
                      s.clients, s.uptime_s, s.firmware, s.firmware_info
               FROM devices d
               LEFT JOIN device_status s ON s.device_id = d.id
               ORDER BY d.id""")
    devices = []
    for r in rows:
        fi = r["firmware_info"]
        firmware_info = None
        if fi:
            try:
                import json as _json
                firmware_info = _json.loads(fi)
            except Exception:
                firmware_info = None
        devices.append({
            "id": r["id"], "name": r["name"], "host": r["host"],
            "role": r["role"], "access": r["access"], "status": r["status"],
            "health_score": r["health_score"], "last_checked": r["last_checked"],
            "clients": r["clients"], "uptime_s": r["uptime_s"],
            "firmware": r["firmware"],
            "firmware_info": firmware_info,
        })

    # Gateway: settings.network_gateway -> device id, if that device exists.
    gw_id = None
    gw_raw = owctl.get_setting("network_gateway")
    if gw_raw not in (None, ""):
        try:
            gw_id = int(gw_raw)
        except (TypeError, ValueError):
            gw_id = None
    gateway = None
    gateway_missing = True
    if gw_id is not None:
        gw_rows = owctl.q("""SELECT d.id, d.name, d.host, d.status, d.health_score,
                              d.last_checked, s.uptime_s, s.firmware, s.firmware_info
                       FROM devices d
                       LEFT JOIN device_status s ON s.device_id = d.id
                       WHERE d.id=?""", (gw_id,))
        if gw_rows:
            g = gw_rows[0]
            fi = g["firmware_info"]
            gateway_firmware_info = None
            if fi:
                try:
                    import json as _json
                    gateway_firmware_info = _json.loads(fi)
                except Exception:
                    gateway_firmware_info = None
            gateway = {
                "id": g["id"], "name": g["name"], "host": g["host"],
                "status": g["status"], "health_score": g["health_score"],
                "firmware": g["firmware"], "uptime_s": g["uptime_s"],
                "last_checked": g["last_checked"],
                "firmware_info": gateway_firmware_info,
            }
            gateway_missing = False

    # Totals.
    online = sum(1 for d in devices if d["status"] == "online")
    offline = sum(1 for d in devices if d["status"] == "offline")
    clients_sum = 0
    for d in devices:
        if d["clients"] is not None:
            clients_sum += int(d["clients"])

    findings = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for r in owctl.q("SELECT severity, COUNT(*) AS c FROM active_findings GROUP BY severity"):
        sev = (r["severity"] or "").upper()
        if sev in findings:
            findings[sev] = int(r["c"])

    # Aggregate current Mbps from the latest 2 traffic samples per device+iface.
    rx_mbps = tx_mbps = 0.0
    samples = owctl.q("""SELECT device_id, iface, ts, rx_bytes, tx_bytes
                   FROM traffic_samples ORDER BY device_id, iface, ts DESC""")
    by_key = {}
    for s in samples:
        key = (s["device_id"], s["iface"])
        by_key.setdefault(key, []).append(s)
    for key, samps in by_key.items():
        if len(samps) < 2:
            continue
        latest, prev = samps[0], samps[1]
        try:
            t_new = datetime.fromisoformat(latest["ts"])
            t_old = datetime.fromisoformat(prev["ts"])
            dt = (t_new - t_old).total_seconds()
        except Exception:
            continue
        if dt <= 0:
            continue
        rx_mbps += ((latest["rx_bytes"] - prev["rx_bytes"]) * 8) / (dt * 1_000_000)
        tx_mbps += ((latest["tx_bytes"] - prev["tx_bytes"]) * 8) / (dt * 1_000_000)

    # Status rule.
    if not devices:
        status = "offline"
    elif any(d["status"] == "offline" for d in devices):
        status = "offline"
    elif any(d["status"] in ("unknown", "error") for d in devices) or gateway_missing:
        status = "degraded"
    else:
        status = "online"

    recent_offline = []
    for r in owctl.q("SELECT device_name, went_offline, went_online, offline_seconds "
               "FROM offline_events ORDER BY id DESC LIMIT 5"):
        try:
            t_off = datetime.fromisoformat(r["went_offline"].replace(" ", "T"))
            if r["went_online"]:
                t_on = datetime.fromisoformat(r["went_online"].replace(" ", "T"))
            else:
                t_on = datetime.fromisoformat(owctl.now().replace(" ", "T"))
            offline_seconds = max(0, int((t_on - t_off).total_seconds()))
        except Exception:
            offline_seconds = 0
        recent_offline.append({
            "device_name": r["device_name"],
            "went_offline": r["went_offline"],
            "went_online": r["went_online"],
            "offline_seconds": offline_seconds,
        })

    vlans = list_vlans()

    return {
        "status": status,
        "gateway_missing": gateway_missing,
        "gateway": gateway,
        "devices": devices,
        "totals": {
            "devices": len(devices),
            "online": online,
            "offline": offline,
            "clients": clients_sum,
            "rx_mbps": round(rx_mbps, 2),
            "tx_mbps": round(tx_mbps, 2),
            "findings": findings,
        },
        "vlans": vlans,
        "recent_offline": recent_offline,
    }


@owctl.app.post("/api/devices")
async def add_device(request: Request):
    d = await request.json()
    host = (d.get("host") or "").strip()
    if not re.fullmatch(r"[\d.]+", host):
        raise HTTPException(400, "host must be an IPv4 address")
    name = (d.get("name") or host).strip()
    role = (d.get("role") or "router").strip().lower()
    try:
        did = owctl.execute(
            "INSERT INTO devices(name,host,role,access,ssh_port,ssh_user,ssh_password,key_path,"
            "luci_user,luci_pass,luci_port,added_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
            (name, host, role, d.get("access") or "ssh",
             int(d.get("ssh_port") or 22), d.get("ssh_user") or "root",
             owctl._store_device_cred(d.get("ssh_password") or ""), d.get("key_path") or "",
             d.get("luci_user") or "root", owctl._store_device_cred(d.get("luci_pass") or ""),
             (int(d["luci_port"]) if d.get("luci_port") else None), owctl.now()))
    except sqlite3.IntegrityError:
        raise HTTPException(400, f"host {host} already registered")
    return {"id": did}


@owctl.app.put("/api/devices/{did}")
async def update_device(request: Request, did: int):
    d = await request.json()
    cur = owctl.q("SELECT * FROM devices WHERE id=?", (did,))
    if not cur:
        raise HTTPException(404, "device not found")
    dev = cur[0]
    # Ensure role is set for existing rows
    current_role = dev["role"] or "router"
    
    def g(k, dflt=None):
        return d.get(k) if d.get(k) is not None else dflt
    role = g("role", current_role)
    if role is not None:
        role = role.strip().lower()
    # Security: an empty/whitespace password means "keep existing" (the UI only
    # sends a real value when the user actually changes it). Prevents redaction
    # from being mistaken for a credential wipe.
    ssh_pw = (d.get("ssh_password") or "").strip()
    ssh_pw = owctl._store_device_cred(ssh_pw) if ssh_pw else (dev["ssh_password"] or "")
    luci_pw = (d.get("luci_pass") or "").strip()
    luci_pw = owctl._store_device_cred(luci_pw) if luci_pw else (dev["luci_pass"] or "")
    owctl.execute("UPDATE devices SET name=?, role=?, access=?, ssh_port=?, ssh_user=?, ssh_password=?, "
            "key_path=?, luci_user=?, luci_pass=?, luci_port=?, tags=? WHERE id=?",
            (g("name", dev["name"]), role, g("access", dev["access"]),
             int(g("ssh_port", dev["ssh_port"] or 22)), g("ssh_user", dev["ssh_user"]),
             ssh_pw, g("key_path", dev["key_path"]),
             g("luci_user", dev["luci_user"]), luci_pw,
             (int(g("luci_port", dev.get("luci_port") or 0)) or None),
             d.get("tags", dev["tags"]), did))
    return {"ok": True}


@owctl.app.delete("/api/devices/{did}")
def delete_device(did: int):
    owctl.execute("DELETE FROM active_findings WHERE device_id=?", (did,))
    owctl.execute("DELETE FROM devices WHERE id=?", (did,))
    # Drop the in-memory heartbeat state for this device so the dict doesn't
    # grow unboundedly as devices are added/removed over time.
    owctl._HEARTBEAT_STATE.pop(did, None)
    return {"ok": True}


@owctl.app.post("/api/devices/{did}/check")
def device_check(did: int):
    cur = owctl.q("SELECT * FROM devices WHERE id=?", (did,))
    if not cur:
        raise HTTPException(404, "device not found")
    try:
        return owctl.check_device(cur[0])
    except Exception as e:
        owctl.record_heartbeat(cur[0], False)
        owctl.execute("UPDATE devices SET status='offline' WHERE id=?", (did,))
        raise HTTPException(502, owctl.enrich_device_error(cur[0], str(e), "device_check"))


@owctl.app.post("/api/devices/{did}/test")
def device_test(did: int):
    cur = owctl.q("SELECT * FROM devices WHERE id=?", (did,))
    if not cur:
        raise HTTPException(404, "device not found")
    dev = cur[0]
    if dev["access"] == "ssh":
        return owctl.ssh_test(dev)
    if dev["access"] == "luci":
        return owctl.luci_test(dev)
    return {"ok": False, "detail": "device has no management access configured"}


@owctl.app.post("/api/devices/{did}/push-key")
def device_push_key(did: int):
    cur = owctl.q("SELECT * FROM devices WHERE id=?", (did,))
    if not cur:
        raise HTTPException(404, "device not found")
    if cur[0]["access"] != "ssh":
        raise HTTPException(400, "push-key requires ssh access")
    try:
        return owctl.push_ssh_key(cur[0])
    except HTTPException:
        raise
    except Exception as e:
        owctl.log_action(cur[0], 'push_key', '', ok=False, error=str(e))
        raise HTTPException(502, str(e))


@owctl.app.post("/api/devices/{did}/backup")
def device_backup(did: int):
    cur = owctl.q("SELECT * FROM devices WHERE id=?", (did,))
    if not cur:
        raise HTTPException(404, "device not found")
    try:
        return {"backup": owctl.do_backup(cur[0])}
    except HTTPException:
        raise
    except Exception as e:
        owctl.log_action(cur[0], 'backup', '', ok=False, error=str(e))
        raise HTTPException(502, owctl.enrich_device_error(cur[0], str(e), "backup"))


@owctl.app.post("/api/devices/{did}/restore")
async def device_restore(request: Request, did: int):
    cur = owctl.q("SELECT * FROM devices WHERE id=?", (did,))
    if not cur:
        raise HTTPException(404, "device not found")
    d = await request.json()
    path = d.get("path", "")
    if not path:
        raise HTTPException(400, "backup path required")
    try:
        return await run_in_threadpool(owctl.do_restore, cur[0], path)
    except HTTPException:
        raise
    except Exception as e:
        owctl.log_action(cur[0], 'restore', '', ok=False, error=str(e))
        raise HTTPException(502, owctl.enrich_device_error(cur[0], str(e), "restore"))


@owctl.app.post("/api/vlans/apply")
async def apply_vlan(request: Request):
    """Apply VLAN config across multiple devices. ``apply=false`` (LuCI 'Save')
    commits without restarting daemons; ``apply=true``/omitted (default) also applies."""
    d = await request.json()
    vlan_id = d.get("vlan_id")
    name = d.get("name", f"vlan_{vlan_id}")
    subnet = d.get("subnet", "192.168.10.0/24")
    dhcp = d.get("dhcp", True)
    devices = d.get("devices", [])
    router_id = d.get("router_id")
    apply = d.get("apply") is not False  # True unless explicitly false
    if not vlan_id or not devices:
        raise HTTPException(400, "vlan_id and devices required")
    # Validate BEFORE the per-device loop so mocks/SSH never see a raw value
    # (injection choke point: vlan_id lands in uci shell text on the device).
    vlan_id = owctl._valid_vlan_id(vlan_id)
    results = []
    for did in devices:
        cur = owctl.q("SELECT * FROM devices WHERE id=?", (did,))
        if not cur:
            continue
        try:
            r = await run_in_threadpool(owctl.do_vlan, cur[0], vlan_id, name, subnet, dhcp, devices, router_id, apply=apply)
            results.append(r)
        except Exception as e:
            results.append({"device": cur[0]["name"], "ok": False, "error": str(e)})
    if results and any(r.get("ok") for r in results):
        owctl.execute("INSERT INTO vlans(vlan_id, name, subnet, dhcp, created_at) VALUES(?,?,?,?,?) "
                "ON CONFLICT(vlan_id) DO UPDATE SET name=excluded.name, subnet=excluded.subnet, "
                "dhcp=excluded.dhcp, created_at=excluded.created_at",
                (str(vlan_id), name, subnet, 1 if dhcp else 0, owctl.now()))
    return {"results": results}


@owctl.app.get("/api/devices/{did}/vlans/{vid}")
def read_vlan_state_endpoint(did: int, vid: int):
    """Live state of one VLAN on one device — subnet, DHCP, zone policy.
    The UI's 'edit' prefill and post-apply verification both read this."""
    dev = _require_device(did)
    r = owctl.read_vlan_state(dev, vid)
    if r.get("error"):
        if r["error"].startswith("luci-only"):
            return {"device": dev["name"], "vlan_id": str(vid), "configured": False}
        raise HTTPException(502, owctl.enrich_device_error(dev, r["error"], "vlan_read"))
    configured = bool(r.get("subnet") or r.get("dhcp") or r.get("zone"))
    return {"device": dev["name"], "vlan_id": str(vid), "configured": configured,
            "subnet": r.get("subnet"), "dhcp": r.get("dhcp"), "zone": r.get("zone")}


@owctl.app.post("/api/vlans/delete")
async def delete_vlan(request: Request):
    """Remove a VLAN's config from the selected devices (default: all members).
    Body: {vlan_id, devices?: [id,...], apply?: bool (default true)}.
    Clears the membership ledger for each device it touched."""
    d = await request.json()
    vlan_id = d.get("vlan_id")
    if not vlan_id:
        raise HTTPException(400, "vlan_id required")
    vlan_id = owctl._valid_vlan_id(vlan_id)
    apply = d.get("apply") is not False
    devs = [int(x) for x in (d.get("devices") or [])]
    if not devs:
        devs = [m["device_id"] for m in owctl.vlan_members(vlan_id)]
    if not devs:
        # Discovered-but-never-applied VLAN: no membership ledger — ask every
        # SSH device to drop its sections (deletes are idempotent no-ops).
        devs = [r["id"] for r in owctl.q("SELECT id FROM devices WHERE access='ssh'")]
    results = []
    for did in devs:
        cur = owctl.q("SELECT * FROM devices WHERE id=?", (did,))
        if not cur:
            continue
        try:
            r = await run_in_threadpool(owctl.do_vlan_delete, cur[0], vlan_id, apply=apply)
            owctl.delete_vlan_membership(vlan_id, did)
            results.append(r)
        except Exception as e:
            results.append({"device": cur[0]["name"], "ok": False, "error": str(e)})
    if results and any(r.get("ok") for r in results):
        owctl.execute("DELETE FROM vlans WHERE vlan_id=?", (str(vlan_id),))
    return {"results": results}


@owctl.app.get("/api/devices/{did}/routing")
def read_routing_endpoint(did: int):
    """Live routing state of one device: per-interface gateways + static
    routes, the kernel routing table (ip route), policy rules (ip rule), and any
    BGP (bird) config. No mutation."""
    dev = _require_device(did)
    r = owctl.read_routing(dev)
    if r.get("error"):
        if r["error"].startswith("luci-only"):
            return {"device": dev["name"], "configured": False}
        raise HTTPException(502, owctl.enrich_device_error(dev, r["error"], "routing_read"))
    configured = bool(r.get("interfaces") or r.get("ip_routes") or r.get("policy") or (r.get("bgp") or {}).get("present"))
    return {"device": dev["name"], "configured": configured, **r}


@owctl.app.post("/api/devices/{did}/routes")
async def add_route_endpoint(request: Request, did: int):
    """Add or replace a static route on one device.
    Body: {dst, via, metric?, iface?, apply?}. `via` may be a concrete IPv4
    gateway or a logical 'vlan:<id>' (resolved to that VLAN's gateway).
    Idempotent (same dst replaces the existing entry)."""
    dev = _require_device(did)
    d = await request.json()
    dst = (d.get("dst") or "").strip()
    via = (d.get("via") or "").strip()
    metric = d.get("metric")
    iface = d.get("iface") or None
    apply = d.get("apply") is not False
    if not dst or not via:
        raise HTTPException(400, "dst and via are required")
    r = await run_in_threadpool(owctl.do_route, dev, dst, via, metric, iface, apply=apply)
    row = owctl.q("SELECT id FROM routes WHERE dst=? AND policy='default'", (dst,))
    if row:
        owctl._record_route_realization(row[0]["id"], dev["id"], "applied" if apply else "pending")
    return r


@owctl.app.post("/api/devices/{did}/routes/delete")
async def delete_route_endpoint(request: Request, did: int):
    """Remove a static route (by dst) from one device. Body: {dst, iface?}."""
    dev = _require_device(did)
    d = await request.json()
    dst = (d.get("dst") or "").strip()
    iface = d.get("iface") or None
    apply = d.get("apply") is not False
    if not dst:
        raise HTTPException(400, "dst is required")
    return await run_in_threadpool(owctl.do_route_delete, dev, dst, iface, apply=apply)


@owctl.app.post("/api/devices/{did}/policy-routes")
async def policy_route_endpoint(request: Request, did: int):
    """Add a policy-routing table entry on one device.
    Body: {table, match_dst, route_dst, via, iface?, apply?}."""
    dev = _require_device(did)
    d = await request.json()
    table = (d.get("table") or "owctl").strip()
    match_dst = (d.get("match_dst") or "").strip()
    route_dst = (d.get("route_dst") or "").strip()
    via = (d.get("via") or "").strip()
    iface = d.get("iface") or None
    apply = d.get("apply") is not False
    if not (match_dst and route_dst and via):
        raise HTTPException(400, "match_dst, route_dst and via are required")
    return await run_in_threadpool(owctl.do_policy_route, dev, table, match_dst, route_dst, via, iface, apply=apply)


@owctl.app.post("/api/devices/{did}/bgp")
async def bgp_endpoint(request: Request, did: int):
    """Install/replace a minimal bird-based BGP config on one device.
    Body: {asn, peers:[{addr, as, name?}], apply?}. Installs the `bird` package
    if missing, writes /etc/birdc/owctl.bgp, and (re)starts BGP."""
    dev = _require_device(did)
    d = await request.json()
    asn = d.get("asn")
    peers = d.get("peers") or []
    apply = d.get("apply") is not False
    if not peers:
        raise HTTPException(400, "at least one BGP peer is required")
    return await run_in_threadpool(owctl.do_bgp, dev, asn, peers, apply=apply)


@owctl.app.get("/api/routes")
def fleet_routes():
    """One-network view: every logical route with its per-device realization
    (applied/pending/failed) and the union of devices it is expected on. Read
    from the DB ledger — no SSH, instant."""
    rows = owctl.q("SELECT r.*, GROUP_CONCAT(rd.device_id) AS device_ids, "
             "GROUP_CONCAT(rd.state) AS states FROM routes r "
             "LEFT JOIN routes_devices rd ON rd.route_id = r.id GROUP BY r.id ORDER BY r.id")
    out = []
    for r in rows:
        ids = [int(x) for x in (r["device_ids"] or "").split(",") if x.strip().isdigit()]
        states = (r["states"] or "").split(",")
        devs = []
        for i, s in zip(ids, states):
            dr = owctl.q("SELECT id, name FROM devices WHERE id=?", (i,))
            devs.append({"id": i, "name": dr[0]["name"] if dr else "?", "state": s or "?"})
        out.append({**r, "devices": devs})
    return {"routes": out}


@owctl.app.post("/api/routes/apply")
async def fleet_routes_apply(request: Request):
    """Apply a logical route to the set of devices it is expected on.
    Body: {dst, via, metric?, devices:[id,...], apply?}. `via` may be
    'vlan:<id>'. Per-device error isolation: one box failing is reported, not
    fatal to the batch."""
    d = await request.json()
    dst = (d.get("dst") or "").strip()
    via = (d.get("via") or "").strip()
    metric = d.get("metric")
    apply = d.get("apply") is not False
    if not (dst and via):
        raise HTTPException(400, "dst and via are required")
    dids = [int(x) for x in (d.get("devices") or [])]
    if not dids:
        raise HTTPException(400, "devices (list of ids) is required")
    rid = owctl.q("SELECT id FROM routes WHERE dst=? AND policy='default'", (dst,))
    if rid:
        owctl.execute("UPDATE routes SET via=?, metric=?, note=?, created_at=? WHERE id=?",
                (via, metric, d.get("note"), owctl.now(), rid[0]["id"]))
        rid = rid[0]["id"]
    else:
        rid = owctl.execute("INSERT INTO routes(dst, via, metric, policy, note, created_at) VALUES(?,?,?,?,?,?)",
                      (dst, via, metric, "default", d.get("note"), owctl.now()))
    results = []
    for did in dids:
        cur = owctl.q("SELECT * FROM devices WHERE id=?", (did,))
        if not cur:
            results.append({"device_id": did, "name": "?", "ok": False, "error": "unknown device"})
            continue
        try:
            r = await run_in_threadpool(owctl.do_route, cur[0], dst, via, metric, None, apply=apply)
            owctl._record_route_realization(rid, did, "applied" if apply else "pending")
            results.append({"device_id": did, "name": cur[0]["name"], "ok": True, **r})
        except Exception as e:
            owctl._record_route_realization(rid, did, "failed")
            results.append({"device_id": did, "name": cur[0]["name"], "ok": False, "error": str(e)})
    ok = sum(1 for r in results if r["ok"])
    return {"ok": ok, "failed": len(results) - ok, "results": results}


@owctl.app.post("/api/routes/delete")
async def fleet_routes_delete(request: Request):
    """Remove a logical route (by dst) from the selected devices and drop the
    ledger rows. Body: {dst, devices?: [id,...], apply?}."""
    d = await request.json()
    dst = (d.get("dst") or "").strip()
    apply = d.get("apply") is not False
    if not dst:
        raise HTTPException(400, "dst is required")
    row = owctl.q("SELECT id FROM routes WHERE dst=? AND policy='default'", (dst,))
    rid = row[0]["id"] if row else None
    dids = [int(x) for x in (d.get("devices") or [])]
    if rid and not dids:
        dids = [r["device_id"] for r in owctl.q("SELECT device_id FROM routes_devices WHERE route_id=?", (rid,))]
    if not dids:
        dids = [r["id"] for r in owctl.q("SELECT id FROM devices WHERE access='ssh'")]
    results = []
    for did in dids:
        cur = owctl.q("SELECT * FROM devices WHERE id=?", (did,))
        if not cur:
            continue
        try:
            await run_in_threadpool(owctl.do_route_delete, cur[0], dst, None, apply=apply)
            if rid:
                owctl.execute("DELETE FROM routes_devices WHERE route_id=? AND device_id=?", (rid, did))
            results.append({"device_id": did, "name": cur[0]["name"], "ok": True})
        except Exception as e:
            results.append({"device_id": did, "name": cur[0]["name"], "ok": False, "error": str(e)})
    if rid:
        owctl.execute("DELETE FROM routes WHERE id=?", (rid,))
    ok = sum(1 for r in results if r["ok"])
    return {"ok": ok, "failed": len(results) - ok, "results": results}


@owctl.app.post("/api/dhcp/apply")
async def apply_dhcp(request: Request):
    """Apply a FULL per-VLAN DHCP section to a device: pool (start/limit/lease/mode),
    network overrides (netmask/broadcast/local), behavior flags (no_resolve/
    notransfer/no_default), DHCP options, static leases, and odhcpd IPv6 keys.

    The whole section is managed per-VLAN (``dhcp.<iface>``). Omitting an
    option/lease or unchecking a flag removes it (lists are replaced wholesale,
    flags are deleted). ``enabled=False`` deletes the section entirely."""
    d = await request.json()
    did = d.get("did")
    vlan_id = d.get("vlan_id")
    iface = d.get("interface", f"vlan_{vlan_id}")
    enabled = d.get("enabled", True)
    if not did or not vlan_id:
        raise HTTPException(400, "did and vlan_id required")
    cur = owctl.q("SELECT * FROM devices WHERE id=?", (did,))
    if not cur:
        raise HTTPException(404, "device not found")
    dev = cur[0]
    if dev["access"] != "ssh":
        raise HTTPException(400, "DHCP config requires SSH access")

    # ---- validate the values we will quote into a shell script ----
    iface_s = str(iface).strip()
    if not re.match(r"^[A-Za-z0-9_]+$", iface_s):
        raise HTTPException(400, "invalid interface name")
    # subnet + ifname (network package) — the interface's L3 address
    subnet = (d.get("subnet") or "").strip()
    ifname = (d.get("ifname") or "").strip()
    if ifname and not re.match(r"^[A-Za-z0-9_.\-]+$", ifname):
        raise HTTPException(400, "invalid ifname")
    if subnet and not owctl._parse_subnet(subnet):
        raise HTTPException(400, "invalid subnet (expected a.b.c.d/prefix)")
    start = d.get("start", 100)
    limit = d.get("limit", 150)
    lease_time = str(d.get("lease_time") or "12h").strip()
    dhcpv4 = (d.get("dhcpv4") or "server").strip()
    if dhcpv4 not in ("server", "relay", "none"):
        raise HTTPException(400, "dhcpv4 must be one of: server, relay, none")
    for _k in ("start", "limit"):
        if d.get(_k) not in (None, ""):
            try:
                int(d[_k])
            except (TypeError, ValueError):
                raise HTTPException(400, f"{_k} must be an integer")
    netmask = (d.get("netmask") or "").strip()
    broadcast = (d.get("broadcast") or "").strip()
    if netmask and not re.match(r"^\d{1,3}(\.\d{1,3}){3}$", netmask):
        raise HTTPException(400, "invalid netmask")
    if broadcast and not re.match(r"^\d{1,3}(\.\d{1,3}){3}$", broadcast):
        raise HTTPException(400, "invalid broadcast")
    # options: list of strings (raw dnsmasq/odhcpd option text)
    options = [str(o).strip() for o in (d.get("options") or []) if str(o).strip()]
    for o in options:
        if not re.match(r"^[A-Za-z0-9_@,.:=%-]+$", o):
            raise HTTPException(400, f"invalid DHCP option value: {o!r}")
    # static leases: list of {name, mac, ip}
    leases_in = d.get("static_leases") or []
    leases = []
    for h in leases_in:
        name = str(h.get("name") or "").strip()
        mac = str(h.get("mac") or "").strip().lower()
        ip = str(h.get("ip") or "").strip()
        if not (name and mac and ip):
            raise HTTPException(400, f"static lease missing name/mac/ip: {h!r}")
        if not re.match(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$", mac):
            raise HTTPException(400, f"invalid MAC address: {mac!r}")
        if not re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ip):
            raise HTTPException(400, f"invalid lease IP: {ip!r}")
        leases.append({"name": name, "mac": mac, "ip": ip})
    # ipv6 (odhcpd)
    ip6 = d.get("ipv6") or {}
    if ip6.get("dhcpv6") and str(ip6["dhcpv6"]).strip() not in ("server", "relay", "none"):
        raise HTTPException(400, "ipv6.dhcpv6 must be one of: server, relay, none")
    if ip6.get("ra_management") and str(ip6["ra_management"]).strip() not in ("0", "1", "2", "3"):
        raise HTTPException(400, "ipv6.ra_management must be 0, 1, 2 or 3")

    cfg = {
        "start": d.get("start"),
        "limit": d.get("limit"),
        "lease_time": lease_time,
        "dhcpv4": dhcpv4,
        "netmask": netmask or None,
        "broadcast": broadcast or None,
        "local": bool(d.get("local")),
        "subnet": subnet or None,
        "ifname": ifname or None,
        "no_resolve": bool(d.get("no_resolve")),
        "notransfer": bool(d.get("notransfer")),
        "no_default": bool(d.get("no_default")),
        "options": options,
        "static_leases": leases,
        "ipv6": {k: v for k, v in ip6.items() if v not in (None, "")},
    }

    c = await run_in_threadpool(owctl._ssh_connect, dev)
    try:
        apply = d.get("apply") is not False
        if enabled:
            cmd = owctl.build_dhcp_cmds(iface_s, cfg, apply=apply)
        else:
            cmd = (f"uci -q delete dhcp.{iface_s} || true\n"
                   "uci commit dhcp\n")
            if apply:
                cmd += ("/etc/init.d/dnsmasq reload 2>/dev/null || /etc/init.d/odhcpd reload 2>/dev/null || true\n")
        stdin, stdout, stderr = c.exec_command(cmd, timeout=30)
        out = stdout.read().decode(errors="replace")
        err = stderr.read().decode(errors="replace")
        status = stdout.channel.recv_exit_status()
        if status != 0:
            raise RuntimeError(f"DHCP config failed on {dev['name']}: {(err or out)[:200]}")
        owctl.set_pending(dev, "dhcp", apply)
        owctl.log_action(dev, 'dhcp', f'vlan={vlan_id} enabled={enabled} opts={len(options)} leases={len(leases)}', ok=True)
        owctl.execute("""INSERT INTO dhcp(device_id, vlan_id, iface, start, "limit", lease_time, enabled,
                   options, static_leases, subnet, ifname, ts)
                   VALUES(?,?,?,?,?,?,?,?,?,?,?,?)
                   ON CONFLICT(device_id, vlan_id) DO UPDATE SET
                     iface=excluded.iface, start=excluded.start, "limit"=excluded."limit",
                     lease_time=excluded.lease_time, enabled=excluded.enabled,
                     options=excluded.options, static_leases=excluded.static_leases,
                     subnet=excluded.subnet, ifname=excluded.ifname,
                     ts=excluded.ts""",
                (dev["id"], str(vlan_id), iface_s,
                 int(start) if str(start).isdigit() else 100,
                 int(limit) if str(limit).isdigit() else 150,
                 lease_time, 1 if enabled else 0,
                 json.dumps(options) if options else None,
                 json.dumps(leases) if leases else None,
                 subnet or None,
                 ifname or None,
                 owctl.now()))
        return {"device": dev["name"], "ok": True}
    finally:
        c.close()


@owctl.app.get("/api/dhcp")
def dhcp_read(did: int):
    """Saved + live DHCP config for a device."""
    dev = _require_device(did)
    if dev["access"] != "ssh":
        raise HTTPException(400, "DHCP read requires SSH access on this device")
    return {"saved": owctl._saved_dhcp_rows(dev["id"]), "live": owctl._read_live_dhcp(dev)}


@owctl.app.get("/api/dhcp/leases")
async def get_dhcp_leases(request: Request):
    """Get DHCP leases from a device."""
    did = request.query_params.get("did")
    if not did:
        raise HTTPException(400, "did required")
    cur = owctl.q("SELECT * FROM devices WHERE id=?", (did,))
    if not cur:
        raise HTTPException(404, "device not found")
    dev = cur[0]
    if dev["access"] != "ssh":
        raise HTTPException(400, "DHCP leases require SSH access")
    c = await run_in_threadpool(owctl._ssh_connect, dev)
    try:
        _, out, _ = await run_in_threadpool(owctl._exec_capture, c, "cat /tmp/dhcp.leases 2>/dev/null", timeout=10)
        leases = []
        for line in out.strip().splitlines():
            p = line.split()
            if len(p) >= 4:
                leases.append({"mac": p[1], "ip": p[2], "hostname": p[3] if len(p) > 3 else ""})
        return {"device": dev["name"], "leases": leases}
    finally:
        c.close()


@owctl.app.get("/api/dhcp/devices")
async def dhcp_known_devices(request: Request):
    """Known-device inventory for the IP-reservation picker: active leases +
    ARP neighbors + existing reservations, merged and deduped by MAC.
    Query: did (required), vlan_id (optional — scopes the subnet badge)."""
    did = request.query_params.get("did")
    if not did:
        raise HTTPException(400, "did required")
    dev = owctl.q("SELECT * FROM devices WHERE id=?", (did,))
    if not dev:
        raise HTTPException(404, "device not found")
    dev = dev[0]
    if dev["access"] != "ssh":
        raise HTTPException(400, "known-devices requires SSH access")
    leases = []
    try:
        c = await run_in_threadpool(owctl._ssh_connect, dev)
        try:
            _, out, _ = await run_in_threadpool(owctl._exec_capture, c, "cat /tmp/dhcp.leases 2>/dev/null", timeout=10)
        finally:
            c.close()
        leases = owctl.parse_dhcp_leases(out)
    except Exception:
        leases = []  # leases unavailable -> picker still works from ARP/reservations
    neighbors = owctl.read_arp_neighbors(dev)
    # existing reservations = static leases in the live sections for this VLAN
    reservations = []
    vid = (request.query_params.get("vlan_id") or "").strip()
    if vid:
        try:
            secs = owctl._read_live_dhcp(dev)
            if isinstance(secs, list):
                for sec in secs:
                    if (sec.get("iface") == f"vlan_{vid}"
                            or str(sec.get("vlan_id") or "") == str(vid)):
                        reservations = sec.get("static_leases") or []
                        break
        except Exception:
            reservations = []
    devices = owctl.merge_known_devices(leases, neighbors, reservations)
    owctl.log_action(dev, "dhcp_devices_list", f"leases={len(leases)} arp={len(neighbors)} reserved={len(reservations)}", ok=True)
    return {"device": dev["name"], "count": len(devices), "devices": devices,
            "lease_count": len(leases), "arp_count": len(neighbors)}


@owctl.app.post("/api/dhcp/reserve")
async def dhcp_reserve(request: Request):
    """Reserve (or release) one IP for a MAC on a VLAN — a single-lease upsert
    on the existing per-VLAN DHCP section (atomic, no load-mutate-resend).
    Body: {did, vlan_id, name, mac, ip?, remove?: bool, apply?: bool (default true)}."""
    d = await request.json()
    did = d.get("did")
    vid = str(d.get("vlan_id") or "").strip()
    if not did or not vid:
        raise HTTPException(400, "did and vlan_id required")
    dev = owctl.q("SELECT * FROM devices WHERE id=?", (did,))
    if not dev:
        raise HTTPException(404, "device not found")
    dev = dev[0]
    if dev["access"] != "ssh":
        raise HTTPException(400, "DHCP reserve requires SSH access")
    apply = d.get("apply") is not False
    remove = bool(d.get("remove"))
    name = str(d.get("name") or "").strip()
    mac = owctl.parse_mac(d.get("mac"))
    ip = str(d.get("ip") or "").strip()
    if not mac:
        raise HTTPException(400, f"invalid MAC address: {d.get('mac')!r}")
    if remove:
        if not name:
            name = "released"
        if not ip:
            raise HTTPException(400, "ip required to remove a reservation")
    else:
        if not (name and ip):
            raise HTTPException(400, "name and ip required to reserve")
        try:
            if ipaddress.ip_address(ip).version != 4:
                raise ValueError
        except ValueError:
            raise HTTPException(400, f"invalid IP address: {ip!r}")

    # Read the current section so we merge, not clobber, and validate against it.
    live = owctl._read_live_dhcp(dev)
    secs = live if isinstance(live, list) else []
    iface = f"vlan_{vid}"
    current = []
    subnet = None
    for sec in secs:
        if (sec.get("iface") == iface or str(sec.get("vlan_id") or "") == str(vid)):
            current = sec.get("static_leases") or []
            subnet = sec.get("subnet")
            break
    if not current and not remove:
        # fall back to the saved row's leases (section may exist only in the DB)
        for row in owctl.q("SELECT * FROM dhcp WHERE device_id=? AND vlan_id=?", (did, vid)):
            try:
                current = json.loads(row["static_leases"]) if row["static_leases"] else []
            except Exception:
                current = []
            break
    err = owctl.validate_reservation(ip, mac, subnet=subnet,
                               leases=current)
    if err:
        raise HTTPException(400, err)
    if remove:
        new_leases = owctl.remove_leases(current, mac)
    else:
        new_leases = owctl.merge_leases(current, name, mac, ip)
    cmd = owctl.build_lease_cmds(iface, new_leases, apply=apply)
    c = await run_in_threadpool(owctl._ssh_connect, dev)
    try:
        out, err_out, status = await run_in_threadpool(owctl._exec_capture, c, cmd, timeout=60)
        if status != 0:
            raise RuntimeError(f"reservation failed on {dev['name']}: {(err_out or out).strip()[:200]}")
        owctl.set_pending(dev, "dhcp", apply)
        owctl.log_action(dev, "dhcp_reserve", f"vlan={vid} mac={mac} ip={ip} remove={remove}", ok=True)
        return {"device": dev["name"], "ok": True, "vlan_id": vid, "mac": mac,
                "ip": ip, "removed": remove, "lease_count": len(new_leases)}
    finally:
        c.close()


@owctl.app.post("/api/dns/apply")
async def apply_dns(request: Request):
    """Apply DNS servers for the device's active DHCP/DNS backend (odhcpd or dnsmasq)."""
    d = await request.json()
    did = d.get("did")
    servers = d.get("servers", [])
    search_domains = d.get("search_domains", [])
    # scope: "dhcp" (default — clients get these via option 6 / dnsmasq server),
    # "router" (box's own /etc/resolv.conf, clients untouched), or "both".
    scope = (d.get("scope") or "dhcp").strip().lower()
    if scope not in ("dhcp", "router", "both"):
        raise HTTPException(400, "scope must be one of: dhcp, router, both")
    if not did:
        raise HTTPException(400, "did required")
    cur = owctl.q("SELECT * FROM devices WHERE id=?", (did,))
    if not cur:
        raise HTTPException(404, "device not found")
    dev = cur[0]
    if dev["access"] != "ssh":
        raise HTTPException(400, "DNS config requires SSH access")
    # 'router' is a template sentinel meaning "local only, no upstream"; it is
    # not a real server and must not be written to the device.
    raw_servers = [str(s).strip() for s in (servers or []) if str(s).strip()]
    servers = [s for s in raw_servers if s != "router"]
    if not raw_servers:
        raise HTTPException(400, "provide at least one upstream server (or 'router' for local-only)")
    c = await run_in_threadpool(owctl._ssh_connect, dev)
    try:
        # ponytail: backend detection by uci keys; add other backends here if seen.
        detect, _e, _s = await run_in_threadpool(owctl._exec_capture, c, "uci show dhcp 2>/dev/null; true", timeout=30)
        # odhcpd (OpenWrt 22.03+) runs DHCP when a section has dhcpv4='server'
        backend = "odhcpd" if re.search(r"^dhcp\.\w+\.dhcpv4='?server'?$", detect, re.M) else "dnsmasq"
        apply = d.get("apply") is not False
        cmd = owctl.build_dns_cmds(backend, detect, servers, search_domains, scope=scope, apply=apply)
        stdin, stdout, stderr = c.exec_command(cmd, timeout=30)
        out = stdout.read().decode(errors="replace")
        err = stderr.read().decode(errors="replace")
        status = stdout.channel.recv_exit_status()
        if status != 0:
            raise RuntimeError(f"DNS config failed on {dev['name']}: {(err or out)[:200]}")
        owctl.set_pending(dev, "dns", apply)
        owctl.log_action(dev, 'dns', f'servers={",".join(servers)} backend={backend} scope={scope}', ok=True)
        owctl.execute("""INSERT INTO dns(device_id, servers, search_domains, scope, ts)
                   VALUES(?,?,?,?,?)
                   ON CONFLICT(device_id) DO UPDATE SET
                     servers=excluded.servers, search_domains=excluded.search_domains,
                     scope=excluded.scope, ts=excluded.ts""",
                (dev["id"], ",".join(servers), ",".join(search_domains), scope, owctl.now()))
        return {"device": dev["name"], "ok": True, "servers": servers,
                "resolver": backend, "scope": scope}
    finally:
        c.close()


@owctl.app.get("/api/dns")
def dns_read(did: int):
    """Saved + live DNS config for a device."""
    dev = _require_device(did)
    if dev["access"] != "ssh":
        raise HTTPException(400, "DNS read requires SSH access on this device")
    return {"saved": owctl._saved_dns_rows(dev["id"]), "live": owctl._read_live_dns(dev)}


@owctl.app.get("/api/vlans")
def list_vlans():
    """Known VLANs (recorded when applied). Shape: [{id,name,subnet,dhcp,
    members:[{device_id,name,role}]}] — members is the per-device membership
    ledger (router carries it routed, switches carry it tagged)."""
    rows = owctl.q("SELECT * FROM vlans ORDER BY CAST(vlan_id AS INTEGER) DESC, vlan_id DESC")
    out = []
    for r in rows:
        out.append({"id": r["vlan_id"], "name": r["name"], "subnet": r["subnet"],
                    "dhcp": bool(r["dhcp"]), "created_at": r["created_at"],
                    "members": owctl.vlan_members(r["vlan_id"])})
    return out


def _require_device(did):
    rows = owctl.q("SELECT * FROM devices WHERE id=?", (did,))
    if not rows:
        raise HTTPException(404, "device not found")
    return rows[0]


@owctl.app.get("/api/qos")
def qos_read(did: int):
    """Saved + live QoS config for a device."""
    dev = _require_device(did)
    if dev["access"] != "ssh":
        raise HTTPException(400, "QoS read requires SSH access on this device")
    return {"saved": owctl._saved_qos_row(dev["id"]), "live": owctl._read_live_qos(dev)}


@owctl.app.post("/api/qos/apply")
async def qos_apply(request: Request):
    """Apply SQM settings to a device and record the saved state."""
    d = await request.json()
    dev = _require_device(int(d.get("did") or 0))
    cfg = {
        "enabled": bool(d.get("enabled", True)),
        "interface": d.get("interface") or "wan",
        "download_kbps": int(d.get("download_kbps") or 0),
        "upload_kbps": int(d.get("upload_kbps") or 0),
        "qdisc": d.get("qdisc") or "fq_codel",
        "ecn": bool(d.get("ecn", False)),
    }
    await run_in_threadpool(owctl.do_qos, dev, cfg, install_if_missing=bool(d.get("install_if_missing", False)),
           apply=d.get("apply") is not False)
    owctl.execute("""INSERT INTO qos(device_id, enabled, interface, download_kbps, upload_kbps, qdisc, ecn, ts)
               VALUES(?,?,?,?,?,?,?,?)
               ON CONFLICT(device_id) DO UPDATE SET enabled=excluded.enabled,
                 interface=excluded.interface, download_kbps=excluded.download_kbps,
                 upload_kbps=excluded.upload_kbps, qdisc=excluded.qdisc, ecn=excluded.ecn, ts=excluded.ts""",
            (dev["id"], 1 if cfg["enabled"] else 0, cfg["interface"], cfg["download_kbps"],
             cfg["upload_kbps"], cfg["qdisc"], 1 if cfg["ecn"] else 0, owctl.now()))
    return {"ok": True, "device": dev["name"], "saved": owctl._saved_qos_row(dev["id"])}


@owctl.app.get("/api/firewall")
def firewall_read(did: int):
    """Saved + live firewall config for a device."""
    dev = _require_device(did)
    if dev["access"] != "ssh":
        raise HTTPException(400, "firewall read requires SSH access on this device")
    return {"saved": owctl._saved_fw_rows(dev["id"]), "live": owctl._read_live_firewall(dev)}


@owctl.app.post("/api/firewall/apply")
async def firewall_apply(request: Request):
    """Apply one firewall change: kind = forward | rule | zone. Record saved state."""
    d = await request.json()
    dev = _require_device(int(d.get("did") or 0))
    apply = d.get("apply") is not False
    kind = (d.get("kind") or "").strip()
    if kind == "forward":
        rule = d.get("rule") or {}
        await run_in_threadpool(owctl.do_fw_forward, dev, rule, apply=apply)
        owctl.execute("""INSERT INTO fw_rules(device_id, kind, name, proto, src_dport, dest_ip, dest_port, ts)
                   VALUES(?,?,?,?,?,?,?,?)
                   ON CONFLICT(device_id, kind, name) DO UPDATE SET proto=excluded.proto,
                     src_dport=excluded.src_dport, dest_ip=excluded.dest_ip,
                     dest_port=excluded.dest_port, ts=excluded.ts""",
                (dev["id"], "forward", (rule.get("name") or "").strip(),
                 rule.get("proto"), rule.get("src_dport"), rule.get("dest_ip"),
                 rule.get("dest_port"), owctl.now()))
    elif kind == "rule":
        rule = d.get("rule") or {}
        await run_in_threadpool(owctl.do_fw_rule, dev, rule, apply=apply)
        owctl.execute("""INSERT INTO fw_rules(device_id, kind, name, src_zone, dst_zone, target, ts)
                   VALUES(?,?,?,?,?,?,?)
                   ON CONFLICT(device_id, kind, name) DO UPDATE SET src_zone=excluded.src_zone,
                     dst_zone=excluded.dst_zone, target=excluded.target, ts=excluded.ts""",
                (dev["id"], "rule", (rule.get("name") or "").strip(),
                 rule.get("src"), rule.get("dest"), rule.get("target"), owctl.now()))
    elif kind == "zone":
        zone = (d.get("zone") or "").strip()
        policies = d.get("policies") or {}
        await run_in_threadpool(owctl.do_zone_policy, dev, zone, policies, apply=apply)
    else:
        raise HTTPException(400, "kind must be one of: forward, rule, zone")
    return {"ok": True, "device": dev["name"], "kind": kind}


@owctl.app.delete("/api/firewall/{did}/rule/{name}")
def firewall_delete_rule(did: int, name: str):
    dev = _require_device(did)
    owctl.delete_fw_rule(dev, name)
    owctl.execute("DELETE FROM fw_rules WHERE device_id=? AND kind='rule' AND name=?",
            (dev["id"], name.strip()))
    return {"ok": True, "device": dev["name"]}


@owctl.app.delete("/api/firewall/{did}/forward/{name}")
def firewall_delete_forward(did: int, name: str):
    dev = _require_device(did)
    owctl.delete_fw_forward(dev, name)
    owctl.execute("DELETE FROM fw_rules WHERE device_id=? AND kind='forward' AND name=?",
            (dev["id"], name.strip()))
    return {"ok": True, "device": dev["name"]}


@owctl.app.post("/api/vlans/discover")
async def discover_vlans_endpoint(request: Request):
    """Scan all SSH-accessible devices for configured VLANs (with subnet/dhcp) and record them."""
    devs = owctl.q("SELECT * FROM devices WHERE access='ssh' ORDER BY id")
    results = []
    for dev in devs:
        results.append(owctl.discover_vlans(dev))
    # Union of VLAN ids across devices (switch-only VLANs included via parse_vlan_ids),
    # with details (subnet/dhcp) attached where an interface section provided them.
    merged = {}
    for r in results:
        det = r.get("details") or {}
        ids = set(r.get("vlans") or []) | set(det.keys())
        for vid in ids:
            d = det.get(vid, {})
            m = merged.setdefault(vid, {"subnet": None, "dhcp": False})
            if d.get("subnet"):
                m["subnet"] = d["subnet"]
            if d.get("dhcp"):
                m["dhcp"] = True
    for vid, info in merged.items():
        owctl._upsert_discovered_vlan(str(vid), f"vlan_{vid}", info["subnet"],
                                1 if info["dhcp"] else None)
    all_ids = sorted((int(v) for v in merged), reverse=True)
    owctl.log_action(None, "vlan_discover", f"devices_scanned={len(devs)} vlans_found={len(merged)}", ok=True)
    return {"devices_scanned": len(devs), "results": results,
            "vlans_found": all_ids, "vlans": list_vlans()}


@owctl.app.get("/api/devices/{did}/switch-ports")
def get_switch_ports(did: int):
    """Read switch-port VLAN assignments (the `switch` package) from a device.
    WiFi-only APs return an empty switches map, not an error."""
    dev = _require_device(did)
    if dev["access"] != "ssh":
        raise HTTPException(400, "switch port read requires SSH access")
    r = owctl.read_switch_ports(dev)
    if r.get("error"):
        # A missing switch package is a normal, non-fatal condition.
        if r["error"].startswith("luci-only") or r["error"] == "no switch":
            return {"device": dev["name"], "switches": {}}
        raise HTTPException(502, owctl.enrich_device_error(dev, r["error"], "switch_read"))
    return {"device": dev["name"], "switches": r.get("switches") or {}}


@owctl.app.post("/api/devices/{did}/switch-ports")
async def apply_switch_ports(request: Request, did: int):
    """Assign switch ports to a VLAN on one device. Body:
    {switch?: 'switch0', vlan_id: int, ports: ['1','2'...], tag?: int,
     apply?: bool (default true)}. Replaces the port list for that VLAN."""
    d = await request.json()
    dev = _require_device(did)
    apply = d.get("apply") is not False
    vlan_id = d.get("vlan_id")
    if not vlan_id:
        raise HTTPException(400, "vlan_id required")
    r = await run_in_threadpool(owctl.do_vlan_port, dev, d.get("switch", "switch0"), vlan_id,
                     d.get("ports") or [], d.get("tag"), apply=apply)
    return r


@owctl.app.get("/api/switch-map")
def switch_map():
    """Network-wide switch-port map: for every switch-capable device, the
    live per-port view — which physical port carries which VLAN (untagged /
    tagged) and whether that port is currently linked. The 'one device'
    physical-layer overview. Live read (no caching): each box is queried for
    its `switch` UCI assignments and its sysfs link state, then joined by
    port index. Boxes without a switch (wifi-only APs) are reported with an
    empty ports map, not an error."""
    devs = owctl.q("SELECT * FROM devices ORDER BY id")
    out = []
    for dev in devs:
        if dev["access"] != "ssh":
            out.append({"device_id": dev["id"], "name": dev["name"], "host": dev["host"],
                        "online": dev["status"] == "online", "has_switch": False,
                        "ports": {}, "error": "luci-only"})
            continue
        r = owctl.read_switch_ports(dev)
        if r.get("error") and not r["error"].startswith("luci-only"):
            out.append({"device_id": dev["id"], "name": dev["name"], "host": dev["host"],
                        "online": dev["status"] == "online", "has_switch": False,
                        "ports": {}, "error": r["error"]})
            continue
        switches = r.get("switches") or {}
        # One physical switch per box is the normal case; take the first.
        first_switch = next(iter(switches.values())) if switches else {}
        assignments = first_switch or {}
        status = owctl.read_switch_port_map(dev)
        ports = owctl.build_switch_map(assignments, status)
        ports_json = {str(k): v for k, v in ports.items()}
        linked = sum(1 for p in ports_json.values() if p.get("up"))
        out.append({"device_id": dev["id"], "name": dev["name"], "host": dev["host"],
                    "online": dev["status"] == "online",
                    "has_switch": bool(ports_json),
                    "port_count": len(ports_json), "linked": linked,
                    "ports": ports_json, "error": None})
    return {"device_count": len(out),
            "switch_devices": sum(1 for d in out if d["has_switch"]),
            "devices": out}


@owctl.app.get("/api/devices/{did}/packages")
def get_device_packages(did: int):
    """Live software inventory for a device: installed packages, obsolete
    packages (installed but no longer in any feed), and meshd presence.

    Installed/obsolete are JSON arrays persisted in device_status on every
    check, so this is instant (no SSH round-trip) after the first gather.
    """
    import json as _json
    row = owctl.q("SELECT installed_pkgs, obsolete_pkgs, meshd FROM device_status WHERE device_id=?", (did,))
    if not row:
        return {"installed": [], "obsolete": [], "meshd": None, "stale": True}
    def _parse(col):
        v = row[0].get(col)
        if not v:
            return []
        try:
            d = _json.loads(v)
            return d if isinstance(d, list) else []
        except Exception:
            return []
    return {"installed": _parse("installed_pkgs"), "obsolete": _parse("obsolete_pkgs"),
            "meshd": row[0].get("meshd"), "stale": False}


@owctl.app.get("/api/fleet/packages")
def fleet_packages():
    """Fleet-wide package view: installed + upgradable packages on every
    device with a status snapshot, in one table. Lets the user see which
    boxes have which package versions and how many updates are pending
    across the whole network (the 'one device' inventory view).
    No SSH — reads the persisted snapshots."""
    import json as _json
    out = []
    for dev in owctl.q("SELECT * FROM devices ORDER BY id"):
        row = owctl.q("SELECT installed_pkgs, upgradable_pkgs, firmware, ts FROM device_status WHERE device_id=?", (dev["id"],))
        if not row:
            continue
        snap = row[0]
        def _pkgs(col):
            v = snap.get(col)
            if not v:
                return []
            try:
                d = _json.loads(v)
                return d if isinstance(d, list) else []
            except Exception:
                return []
        installed = _pkgs("installed_pkgs")
        upgradable = _pkgs("upgradable_pkgs")
        out.append({
            "device_id": dev["id"], "name": dev["name"], "host": dev["host"],
            "online": dev["status"] == "online",
            "firmware": snap.get("firmware"),
            "snapshot_at": snap.get("ts"),
            "installed_count": len(installed),
            "installed": [{"pkg": p.get("pkg"), "version": p.get("version")} for p in installed if isinstance(p, dict)],
            "upgradable_count": len(upgradable),
            "upgradable": [{"pkg": p.get("pkg"), "installed": p.get("installed"), "available": p.get("available")}
                            for p in upgradable if isinstance(p, dict)],
        })
    upg_by_pkg = {}
    for d in out:
        for u in d["upgradable"]:
            upg_by_pkg.setdefault(u["pkg"], []).append(d["name"])
    return {"device_count": len(out),
            "devices_with_updates": sum(1 for d in out if d["upgradable_count"]),
            "total_updates": sum(d["upgradable_count"] for d in out),
            "updates_by_package": {pkg: names for pkg, names in sorted(upg_by_pkg.items())},
            "devices": out}


@owctl.app.post("/api/fleet/upgrade")
async def fleet_upgrade(request: Request):
    """Upgrade packages on every device (or a scoped subset via
    {devices:[id], packages:[...]}). Runs do_upgrade per device with error
    isolation — one box failing doesn't abort the fleet. Long-running; the
    caller should tolerate a long response."""
    try:
        body = await request.json()
    except Exception:
        body = {}
    devices = body.get("devices") or [d["id"] for d in owctl.q("SELECT id FROM devices ORDER BY id")]
    packages = body.get("packages") or []
    results = []
    for did in devices:
        cur = owctl.q("SELECT * FROM devices WHERE id=?", (did,))
        if not cur:
            results.append({"device_id": did, "name": "?", "ok": False, "error": "unknown device"})
            continue
        dev = cur[0]
        try:
            out = await run_in_threadpool(owctl.do_upgrade, dev, packages)
            results.append({"device_id": did, "name": dev["name"], "ok": True,
                            "output": out[-4000:]})
        except Exception as e:
            results.append({"device_id": did, "name": dev["name"], "ok": False, "error": str(e)})
    ok = sum(1 for r in results if r["ok"])
    return {"ok": ok, "failed": len(results) - ok, "results": results}


@owctl.app.post("/api/devices/{did}/packages/remove")
async def remove_packages(request: Request, did: int):
    """Remove one or more packages from a device (opkg remove -y)."""
    cur = owctl.q("SELECT * FROM devices WHERE id=?", (did,))
    if not cur:
        raise HTTPException(404, "device not found")
    dev = cur[0]
    if dev["access"] != "ssh":
        raise HTTPException(400, "package removal requires SSH access on this device")
    d = await request.json()
    pkgs = d.get("pkgs") or ([d.get("pkg")] if d.get("pkg") else [])
    if not pkgs:
        raise HTTPException(400, "pkg (or pkgs list) required")
    bad = [p for p in pkgs if not re.fullmatch(r"[A-Za-z0-9_.+-]+", str(p))]
    if bad:
        raise HTTPException(400, f"invalid package name(s): {bad}")
    cmd = "opkg remove -y " + " ".join(str(p) for p in pkgs)
    out, err, status = owctl._run_ssh(dev, cmd, "package_remove",
                                f"pkgs={','.join(str(p) for p in pkgs)}", "package removal")
    return {"device": dev["name"], "ok": True, "removed": [str(p) for p in pkgs]}


@owctl.app.post("/api/devices/{did}/guest-wifi")
async def device_guest_wifi(request: Request, did: int):
    """Create or update guest WiFi on a device."""
    cur = owctl.q("SELECT * FROM devices WHERE id=?", (did,))
    if not cur:
        raise HTTPException(404, "device not found")
    d = await request.json()
    ssid = d.get("ssid", "")
    password = d.get("password", "")
    vlan_id = d.get("vlan_id")
    method = d.get("method", "create")
    apply = d.get("apply") is not False
    if method == "delete":
        # Delete guest WiFi config
        c = await run_in_threadpool(owctl._ssh_connect, cur[0])
        try:
            iface_name = f"guest_{ssid.replace(' ', '_').replace('-', '_')}" if ssid else None
            if not iface_name:
                # Try to find existing guest interface
                stdin, stdout, stderr = c.exec_command("uci show wireless | grep -E 'guest|ssid' | grep -v default", timeout=10)
                out = stdout.read().decode()
                if 'wifi-iface' in out:
                    for line in out.strip().split('\n'):
                        if '=' in line:
                            iface = line.split('=')[0].strip()
                            c.exec_command(f"uci delete {iface}")
                c.exec_command("uci commit wireless")
        finally:
            c.close()
        return {"ok": True, "action": "deleted"}
    if not ssid or not password:
        raise HTTPException(400, "ssid and password required")
    try:
        return await run_in_threadpool(owctl.do_guest_wifi, cur[0], ssid, password, vlan_id, apply=apply)
    except HTTPException:
        raise
    except Exception as e:
        owctl.log_action(cur[0], 'guest_wifi', '', ok=False, error=str(e))
        raise HTTPException(502, owctl.enrich_device_error(cur[0], str(e), "guest_wifi"))


@owctl.app.get("/api/devices/{did}/wifi-config")
def get_wifi_config(did: int):
    """Get current WiFi configuration for a device: every wifi-iface section
    (device, ssid, encryption, key presence, network, mode), not just guest ones."""
    cur = owctl.q("SELECT * FROM devices WHERE id=?", (did,))
    if not cur:
        raise HTTPException(404, "device not found")
    dev = cur[0]
    if dev["access"] != "ssh":
        raise HTTPException(400, "WiFi config read requires SSH access on this device")
    c = owctl._ssh_connect(dev)
    try:
        out, _err, _st = owctl._exec_capture(c, "uci show wireless 2>/dev/null", timeout=10)
        ifaces = owctl._parse_wifi_ifaces(out)
        return {"interfaces": ifaces, "ssid": (ifaces[0]["ssid"] if ifaces else None),
                "encryption": (ifaces[0]["encryption"] if ifaces else None),
                "vlan_id": None,
                "meshd": (_snap[0]["meshd"] if (_snap := owctl.q("SELECT meshd FROM device_status WHERE device_id=?", (dev["id"],))) else None),
                "last_check": datetime.now(timezone.utc).isoformat()}
    finally:
        c.close()


@owctl.app.post("/api/devices/{did}/wifi-clone")
async def wifi_clone(request: Request, did: int):
    """Clone the WiFi config of device `did` onto other devices, adapting to
    target hardware: each source wifi-iface is mapped to a target radio of the
    same band (2g/5g/6g). If the target has no matching band, the iface is
    skipped and reported. Ifaces are upserted under a stable per-SSID section
    name, so re-running updates rather than duplicating."""
    cur = owctl.q("SELECT * FROM devices WHERE id=?", (did,))
    if not cur:
        raise HTTPException(404, "device not found")
    src = cur[0]
    body = await request.json()
    targets = body.get("target_ids") or []
    apply = body.get("apply") is not False
    if not targets:
        raise HTTPException(400, "target_ids required")
    c = await run_in_threadpool(owctl._ssh_connect, src)
    try:
        out, _e, _s = await run_in_threadpool(owctl._exec_capture, c, "uci show wireless 2>/dev/null", timeout=10)
    finally:
        c.close()
    ifaces = [i for i in owctl._parse_wifi_ifaces(out) if i.get("mode") == "ap" or not i.get("mode")]
    if not ifaces:
        raise HTTPException(400, f"{src['name']} has no wifi-iface sections to clone")
    results = []
    for tid in targets:
        tcur = owctl.q("SELECT * FROM devices WHERE id=?", (tid,))
        if not tcur:
            results.append({"target_id": tid, "ok": False, "detail": "device not found"})
            continue
        t = tcur[0]
        if t["access"] != "ssh":
            results.append({"target_id": tid, "name": t["name"], "ok": False,
                            "detail": "target needs SSH access"})
            continue
        try:
            radios = owctl._wifi_radios(t)
            if not radios:
                results.append({"target_id": tid, "name": t["name"], "ok": False,
                                "detail": "target has no wireless radios"})
                continue
            applied, skipped = [], []
            cc = await run_in_threadpool(owctl._ssh_connect, t)
            try:
                # Resolve each source iface to a target radio and build its uci
                # script (no commit yet). Bandless sources are reported, not
                # guessed onto "first radio", to avoid silent mis-targeting.
                plans = []  # (ssid, radio, slug, cmd)
                for i in ifaces:
                    want = i.get("band") or ""
                    if not want:
                        skipped.append(f"{i.get('ssid') or i['name']} (source has no band; not targeting a radio)")
                        continue
                    radio = next((r for r, b in radios.items() if b == want), None)
                    if radio is None:
                        skipped.append(f"{i.get('ssid') or i['name']} (no {want} radio)")
                        continue
                    slug, cmd = owctl.build_wifi_clone_cmds(i, radio)
                    plans.append((i.get("ssid") or slug, radio, slug, cmd))
                # Dedupe by target section slug: two source ifaces with the same
                # SSID map to the same `clone_<ssid>` section; keep the first.
                seen_slugs, unique_plans = set(), []
                for p in plans:
                    if p[2] in seen_slugs:
                        skipped.append(f"{p[0]} (same target section as an earlier SSID; skipped)")
                    else:
                        seen_slugs.add(p[2])
                        unique_plans.append(p)
                plans = unique_plans
                if plans:
                    # Clobber guard: a section id we are about to `uci set` must
                    # not already exist as a NON-wifi-iface section (which would
                    # have its type/options wiped). Existing wifi-iface sections
                    # are safe to re-upsert (idempotent re-clone).
                    safe = []
                    for ssid, radio, slug, cmd in plans:
                        o, _e, _st = await run_in_threadpool(owctl._exec_capture, cc,
                            f"uci -q get wireless.{slug} 2>/dev/null", timeout=15)
                        typ = (o or "").strip()
                        if typ and typ != "wifi-iface":
                            skipped.append(f"{ssid} (target section '{slug}' is a '{typ}', not wifi-iface; left untouched)")
                        else:
                            safe.append((ssid, radio, slug, cmd))
                    if safe:
                        tail = "uci commit wireless\n" + ("wifi reload\n" if apply else "")
                        script = "".join(p[3] for p in safe) + tail
                        o, e, st = await run_in_threadpool(owctl._exec_capture, cc, script, timeout=60)
                        if st != 0:
                            for ssid, radio, slug, _cmd in safe:
                                skipped.append(f"{ssid} (uci failed: {(e or o)[:80]})")
                        else:
                            for ssid, radio, slug, _cmd in safe:
                                applied.append(f"{ssid} → {radio}")
                            owctl.set_pending(t, "wireless", apply)
            finally:
                cc.close()
            results.append({"target_id": tid, "name": t["name"], "ok": True,
                            "applied": applied, "skipped": skipped})
            owctl.log_action(t, 'wifi_clone', f'source={src["name"]} applied={len(applied)} skipped={len(skipped)}',
                       ok=True)
        except Exception as e:
            results.append({"target_id": tid, "name": t["name"], "ok": False, "detail": str(e)})
    owctl.log_action(src, 'wifi_clone', f'targets={len(targets)}', ok=True)
    return {"source": src["name"], "results": results}


@owctl.app.post("/api/devices/{did}/mesh")
async def device_mesh(request: Request, did: int):
    """Configure 802.11s mesh on a device (meshd / batman-adv).

    Body: {enabled, mesh_vap, mesh_id, mesh_network, mesh_ctrl, mesh_gw_mode,
           mesh_gw_bcast, mesh_htmode, mesh_channel, mesh_encryption, mesh_key,
           install_if_missing}.
    """
    cur = owctl.q("SELECT * FROM devices WHERE id=?", (did,))
    if not cur:
        raise HTTPException(404, "device not found")
    d = await request.json()
    cfg = {
        "enabled": bool(d.get("enabled", True)),
        "mesh_vap": d.get("mesh_vap") or "radio0",
        "mesh_id": (d.get("mesh_id") or "mesh").strip(),
        "mesh_network": d.get("mesh_network") or "lan",
        "mesh_ctrl": d.get("mesh_ctrl"),
        "mesh_gw_mode": d.get("mesh_gw_mode"),
        "mesh_gw_bcast": d.get("mesh_gw_bcast"),
        "mesh_htmode": d.get("mesh_htmode"),
        "mesh_channel": d.get("mesh_channel"),
        "mesh_encryption": d.get("mesh_encryption") or "none",
        "mesh_key": d.get("mesh_key"),
        "install_if_missing": bool(d.get("install_if_missing", False)),
    }
    if not re.fullmatch(r"[A-Za-z0-9_.\-]+", cfg["mesh_vap"]):
        raise HTTPException(400, f"invalid mesh radio {cfg['mesh_vap']!r}")
    if not re.fullmatch(r"[A-Za-z0-9_.\-]+", cfg["mesh_id"]):
        raise HTTPException(400, f"invalid mesh id {cfg['mesh_id']!r}")
    apply = d.get("apply") is not False
    try:
        return await run_in_threadpool(owctl.do_mesh, cur[0], cfg, apply=apply)
    except HTTPException:
        raise
    except Exception as e:
        owctl.log_action(cur[0], 'mesh', '', ok=False, error=str(e))
        raise HTTPException(502, owctl.enrich_device_error(cur[0], str(e), "mesh_apply"))


@owctl.app.get("/api/devices/{did}/mesh")
def get_mesh_config(did: int):
    """Live mesh config for a device: meshd presence + mesh uci sections."""
    dev = _require_device(did)
    if dev["access"] != "ssh":
        raise HTTPException(400, "mesh read requires SSH access on this device")
    c = owctl._ssh_connect(dev)
    try:
        out, _e, _s = owctl._exec_capture(c, "uci show wireless 2>/dev/null; true", timeout=15)
    finally:
        c.close()
    parsed = owctl.parse_uci_show(out)
    sections = parsed.get("wireless", {})
    mesh_ifaces = []
    for name, opts in sections.items():
        if not isinstance(opts, dict):
            continue
        if opts.get("mode") == "mesh" or name.startswith("mesh"):
            mesh_ifaces.append({k: v for k, v in opts.items() if k != "type"})
    snap = owctl.q("SELECT meshd FROM device_status WHERE device_id=?", (dev["id"],))
    return {"interfaces": mesh_ifaces, "meshd": (snap[0]["meshd"] if snap else None)}


@owctl.app.post("/api/devices/{did}/upgrade")
async def device_upgrade(request: Request, did: int):
    cur = owctl.q("SELECT * FROM devices WHERE id=?", (did,))
    if not cur:
        raise HTTPException(404, "device not found")
    d = await request.json()
    pkgs = d.get("packages") or []
    try:
        return {"output": await run_in_threadpool(owctl.do_upgrade, cur[0], pkgs)}
    except HTTPException:
        raise
    except Exception as e:
        owctl.log_action(cur[0], 'upgrade', '', ok=False, error=str(e))
        raise HTTPException(502, owctl.enrich_device_error(cur[0], str(e), "upgrade"))


def diff_snapshots(old_text: str, new_text: str) -> str:
    """Return a unified diff string between two snapshot texts.

    Pure (no I/O), unit-testable. Uses stdlib difflib.unified_diff with
    no external dependencies. Each input is the serialized snapshot content
    (e.g. sorted-key JSON lines).
    """
    old_lines = old_text.splitlines(keepends=True)
    new_lines = new_text.splitlines(keepends=True)
    diff = difflib.unified_diff(
        old_lines, new_lines, lineterm="", fromfile="old", tofile="new"
    )
    return "".join(diff)


@owctl.app.get("/api/devices/{did}/config-history")
def get_config_history(did: int, request: Request):
    """Return config history for diff view.

    Accepts ``from`` or ``from_`` (and ``to`` or ``to_``) as snapshot ids or
    ISO timestamps.  When both are supplied, returns a unified diff under the
    ``diff`` key with ``from``/``to`` echo keys.  Otherwise returns the
    unchanged list shape so existing callers are unaffected.
    """
    qp = request.query_params
    from_val = qp.get("from") or qp.get("from_")
    to_val = qp.get("to") or qp.get("to_")
    rows = owctl.q(
        "SELECT ts, hash FROM config_history WHERE device_id=? ORDER BY ts DESC LIMIT 20",
        (did,),
    )

    if from_val is not None and to_val is not None:
        # Find the two snapshots by id or ISO timestamp
        # Accept a snapshot id (row id) or an ISO timestamp (ts column value)
        snapshot_a = None
        snapshot_b = None

        # Resolve from snapshot
        if from_val.strip().isdigit():
            row = owctl.q(
                "SELECT ts, hash FROM config_history WHERE device_id=? AND id=?",
                (did, int(from_val.strip())),
            )
        else:
            row = owctl.q(
                "SELECT ts, hash FROM config_history WHERE device_id=? AND ts=?",
                (did, from_val.strip()),
            )
        if row:
            snapshot_a = {"ts": row[0]["ts"], "hash": row[0]["hash"]}

        # Resolve to snapshot
        if to_val.strip().isdigit():
            row = owctl.q(
                "SELECT ts, hash FROM config_history WHERE device_id=? AND id=?",
                (did, int(to_val.strip())),
            )
        else:
            row = owctl.q(
                "SELECT ts, hash FROM config_history WHERE device_id=? AND ts=?",
                (did, to_val.strip()),
            )
        if row:
            snapshot_b = {"ts": row[0]["ts"], "hash": row[0]["hash"]}

        if snapshot_a is not None and snapshot_b is not None:
            # Serialize each snapshot's hash field deterministically:
            # the hash column stores "path=hash;path=hash" — split into pairs,
            # build an ordered dict (sorted by path) and re-join so the diff is
            # deterministic regardless of storage order.
            def _serialize(hash_str: str) -> str:
                pairs = []
                for part in hash_str.split(";"):
                    if "=" in part:
                        path, h = part.split("=", 1)
                        pairs.append((path, h))
                pairs.sort(key=lambda kv: kv[0])
                return ";".join(f"{p}={h}" for p, h in pairs)

            text_a = _serialize(snapshot_a["hash"])
            text_b = _serialize(snapshot_b["hash"])
            unified = diff_snapshots(text_a, text_b)
            return {
                "diff": unified,
                "from": snapshot_a["ts"],
                "to": snapshot_b["ts"],
            }

        # If we couldn't resolve both, fall through to the list view
        pass

    # Normal list-return path (no from/to, or resolution failed)
    return [{"ts": r["ts"], "files": r["hash"].split(";")} for r in rows]


@owctl.app.get("/api/devices/{did}/traffic")
def get_traffic_history(did: int):
    """Return recent traffic samples for charting."""
    rows = owctl.q("SELECT ts, iface, rx_bytes, tx_bytes FROM traffic_samples WHERE device_id=? ORDER BY ts DESC LIMIT 48", (did,))
    return [{"ts": r["ts"], "iface": r["iface"], "rx": r["rx_bytes"], "tx": r["tx_bytes"]} for r in rows]


@owctl.app.get("/api/devices/{did}/bandwidth")
def get_bandwidth(did: int):
    """Calculate current Mbps from latest traffic samples."""
    rows = owctl.q("SELECT ts, iface, rx_bytes, tx_bytes FROM traffic_samples WHERE device_id=? ORDER BY ts DESC LIMIT 200", (did,))
    if len(rows) < 2:
        return {"ifaces": {}}
    by_iface = {}
    for r in rows:
        key = r["iface"]
        if key not in by_iface:
            by_iface[key] = []
        by_iface[key].append(r)
    result = {}
    for iface, samples in by_iface.items():
        if len(samples) < 2:
            continue
        # samples are sorted DESC by ts, so samples[0] is newest
        latest, prev = samples[0], samples[1]
        t_new = datetime.fromisoformat(latest["ts"])
        t_old = datetime.fromisoformat(prev["ts"])
        dt = (t_new - t_old).total_seconds()
        if dt <= 0:
            continue
        rx_mbps = ((latest["rx_bytes"] - prev["rx_bytes"]) * 8) / (dt * 1_000_000)
        tx_mbps = ((latest["tx_bytes"] - prev["tx_bytes"]) * 8) / (dt * 1_000_000)
        result[iface] = {"rx_mbps": round(rx_mbps, 2), "tx_mbps": round(tx_mbps, 2)}
    return {"ifaces": result}


@owctl.app.post("/api/bulk")
async def bulk_actions(request: Request):
    """Execute same action on multiple devices."""
    d = await request.json()
    ids = d.get("ids") or []
    action = d.get("action")  # check, backup, reboot
    results = []
    for did in ids:
        cur = owctl.q("SELECT * FROM devices WHERE id=?", (did,))
        if not cur:
            continue
        dev = cur[0]
        try:
            if action == "check":
                await run_in_threadpool(owctl.check_device, dev)
            elif action == "backup":
                await run_in_threadpool(owctl.do_backup, dev)
            elif action == "reboot":
                await run_in_threadpool(owctl.do_reboot, dev)
            results.append({"id": did, "name": dev["name"], "ok": True})
            owctl.log_action(dev, action or 'unknown', '', ok=True)
        except Exception as e:
            results.append({"id": did, "name": dev["name"], "ok": False, "error": str(e)})
            owctl.log_action(dev, action or 'unknown', '', ok=False, error=str(e))
    return {"results": results}


@owctl.app.get("/api/devices/{did}/logs")
def get_device_logs(did: int):
    """Return recent syslog entries for a device."""
    rows = owctl.q("SELECT ts, message FROM log_entries WHERE device_id=? ORDER BY ts DESC LIMIT 50", (did,))
    return [{"ts": r["ts"], "message": r["message"]} for r in rows]


@owctl.app.post("/api/devices/{did}/reboot")
def device_reboot(did: int):
    cur = owctl.q("SELECT * FROM devices WHERE id=?", (did,))
    if not cur:
        raise HTTPException(404, "device not found")
    try:
        return owctl.do_reboot(cur[0])
    except HTTPException:
        raise
    except Exception as e:
        owctl.log_action(cur[0], 'reboot', '', ok=False, error=str(e))
        raise HTTPException(502, owctl.enrich_device_error(cur[0], str(e), "reboot"))


@owctl.app.post("/api/sweep")
async def sweep(request: Request):
    d = await request.json()
    try:
        return owctl.run_sweep(d.get("spec", ""))
    except RuntimeError as e:
        raise HTTPException(400, str(e))


@owctl.app.get("/api/findings")
def findings():
    return {"active": owctl.q("SELECT * FROM active_findings ORDER BY ts DESC"),
            "history": owctl.q("SELECT * FROM findings ORDER BY id DESC LIMIT 200")}


@owctl.app.post("/api/findings/ack")
async def ack_finding(request: Request):
    d = await request.json()
    did, rule = int(d["device_id"]), d["rule_id"]
    owctl.execute("UPDATE active_findings SET severity='INFO' WHERE device_id=? AND rule_id=?", (did, rule))
    return {"ok": True}


@owctl.app.get("/api/alerts/config")
def alerts_get():
    return owctl.get_alert_cfg()


@owctl.app.put("/api/alerts/config")
async def alerts_put(request: Request):
    owctl.set_alert_cfg(await request.json())
    return {"ok": True}


@owctl.app.get("/api/alerts/log")
def alerts_log():
    return owctl.q("SELECT * FROM alert_log ORDER BY id DESC LIMIT 200")


@owctl.app.post("/api/digest")
async def api_digest(request: Request):
    d = await request.json()
    dry_run = bool(d.get("dry_run"))
    subject, body = await run_in_threadpool(owctl.build_digest)
    if dry_run:
        return {"subject": subject, "body": body}
    result = await run_in_threadpool(owctl.send_digest)
    return {"subject": subject, "body": body, **result}


@owctl.app.get("/api/backups")
def backups():
    return owctl.q("SELECT * FROM backups ORDER BY id DESC LIMIT 100")


@owctl.app.post("/api/backup")
def backup_now():
    """Take a DB backup on demand (admin). The scheduler also snapshots
    automatically (throttled to at most one per hour; manual bypasses the
    throttle). This endpoint takes one immediately (e.g. before a risky
    change) or from the dashboard."""
    res = owctl._db_backup(force=True)
    if not res.get("ok"):
        raise HTTPException(500, res.get("reason") or "backup failed")
    return res


@owctl.app.get("/api/actions")
def actions(limit: int = 100):
    """Read-only audit log of all mutating operations, newest first."""
    return owctl.q("SELECT * FROM owctl_actions ORDER BY ts DESC, id DESC LIMIT ?", (max(1, int(limit)),))


@owctl.app.get("/api/settings")
def settings_get():
    gw_raw = owctl.get_setting("network_gateway")
    gw = None
    if gw_raw not in (None, ""):
        try:
            gw = int(gw_raw)
        except (TypeError, ValueError):
            gw = None
    return {"audit_interval_min": owctl.get_setting("audit_interval_min", "30"),
            "admin_password_set": bool(owctl.ensure_admin_password()),
            "network_gateway": gw,
            "digest_schedule": owctl.digest_schedule()}


@owctl.app.get("/api/auth/status")
def auth_status():
    """Public: tells the client whether first-boot setup is still required.

    Setup is needed until some user has a real password set. Once any account
    has a password, the normal sign-in flow takes over.
    """
    has_pw = owctl.q("SELECT 1 FROM users WHERE password_hash != '' AND enabled=1 LIMIT 1")
    return {"needs_setup": len(has_pw) == 0}


@owctl.app.post("/api/auth/setup")
async def auth_setup(request: Request):
    """Public: first-boot admin setup. Only works when no user has a password set yet."""
    # Reject if any user already has a password (i.e. setup already done).
    existing = owctl.q("SELECT 1 FROM users u WHERE u.password_hash != '' LIMIT 1")
    if existing:
        raise HTTPException(status_code=409, detail="admin password is already set; sign in instead")
    d = await request.json()
    password = (d.get("password") or "").strip()
    confirm = (d.get("confirm") or "").strip()
    if len(password) < 4:
        raise HTTPException(status_code=400, detail="password must be at least 4 characters")
    if len(password.encode("utf-8")) > 72:
        raise HTTPException(status_code=400, detail="password must be at most 72 bytes (UTF-8)")
    if password != confirm:
        raise HTTPException(status_code=400, detail="passwords do not match")
    # Seed the default admin if not present, then set the password.
    owctl._ensure_default_admin()
    user = owctl._user_by_username("admin")
    if not user:
        raise HTTPException(status_code=500, detail="could not seed admin account")
    pw_hash = owctl._hash_password(password)
    owctl.execute("UPDATE users SET password_hash=?, role='admin' WHERE id=?", (pw_hash, user["id"]))
    # Issue a session so the client is logged in immediately.
    tok = owctl._create_session(user["id"])
    return {"session": tok, "expires_in": owctl._SESSION_TTL, "role": user["role"]}


@owctl.app.post("/api/auth/login")
async def auth_login(request: Request):
    """User login. On first boot (no user has a password) the first login seeds
    the admin password; afterwards login only verifies. The seed path is gated
    on "no user has any password set yet" so a later-cleared hash cannot be
    re-seeded by whoever logs in next (takeover)."""
    d = await request.json()
    username = (d.get("username") or "").strip()
    password = (d.get("password") or "").strip()
    if not username or not password:
        raise HTTPException(400, "username and password required")
    user = owctl._user_by_username(username)
    if not user:
        # First boot: no such user. Seed the default admin and continue.
        owctl._ensure_default_admin()
        user = owctl._user_by_username(username)
    if not user:
        raise HTTPException(401, "invalid credentials")
    if not user["enabled"]:
        raise HTTPException(403, "account disabled")
    if not user["password_hash"]:
        # Seed only while NO other account has a password yet (true first-boot).
        # If some account already has one, refusing the seed means a later-cleared
        # admin hash can't be re-seeded by whoever logs in next (takeover).
        if owctl.q("SELECT 1 FROM users WHERE password_hash != '' AND id != ? LIMIT 1", (user["id"],)):
            raise HTTPException(403, "another account already has a password; ask an admin to reset yours")
        user["password_hash"] = owctl._hash_password(password)
        owctl.execute("UPDATE users SET password_hash=?, role='admin' WHERE id=?",
                (user["password_hash"], user["id"]))
    elif not owctl._verify_password(password, user["password_hash"]):
        raise HTTPException(401, "invalid credentials")
    tok = owctl._create_session(user["id"])
    return {"session": tok, "expires_in": owctl._SESSION_TTL, "role": user["role"]}


@owctl.app.post("/api/auth/logout")
async def auth_logout(request: Request):
    auth = request.headers.get("authorization", "").split(" ", 1)
    if len(auth) == 2 and auth[0].lower() == "bearer":
        owctl.execute("DELETE FROM sessions WHERE token=?", (auth[1].strip(),))
    return {"ok": True}


@owctl.app.get("/api/users")
def users_list():
    rows = owctl.q("SELECT id, username, role, enabled, last_login FROM users ORDER BY id")
    return [{"id": r["id"], "username": r["username"], "role": r["role"],
             "enabled": bool(r["enabled"]),
             "last_login": r["last_login"]}
            for r in rows]


@owctl.app.post("/api/users")
async def users_create(request: Request):
    d = await request.json()
    username = (d.get("username") or "").strip()
    password = (d.get("password") or "").strip()
    role = (d.get("role") or "observer").strip()
    if not username or not password:
        raise HTTPException(status_code=400, detail="username and password required")
    # Same policy as first-boot setup, self-service password-change, and the
    # dashboard: min 4 chars, max 72 bytes (bcrypt truncation guard).
    err = owctl._password_policy_error(password)
    if err:
        raise HTTPException(status_code=400, detail=err)
    if role not in owctl._ROLES:
        raise HTTPException(status_code=400, detail=f"role must be one of {owctl._ROLES}")
    if owctl._user_by_username(username):
        raise HTTPException(status_code=409, detail="username exists")
    owctl.execute("INSERT INTO users(username, password_hash, role, enabled, created_at) VALUES(?,?,?,?,?)",
            (username, owctl._hash_password(password), role, 1, owctl.now()))
    return {"ok": True}


@owctl.app.put("/api/users/{uid}")
async def users_update(uid: int, request: Request):
    d = await request.json()
    if not d:
        raise HTTPException(status_code=400, detail="request body required")
    user = owctl._user_by_id(uid)
    if not user:
        raise HTTPException(status_code=404, detail="user not found")
    updates = {}
    if "role" in d and d["role"] in owctl._ROLES:
        updates["role"] = d["role"]
    if "enabled" in d:
        updates["enabled"] = int(bool(d["enabled"]))
    if "password" in d and d["password"]:
        pw = str(d["password"])
        err = owctl._password_policy_error(pw)
        if err:
            raise HTTPException(status_code=400, detail=err)
        updates["password_hash"] = owctl._hash_password(pw)
    if updates:
        owctl.execute(f"UPDATE users SET {', '.join(k+'=?' for k in updates)} WHERE id=?",
                (*updates.values(), uid))
    if "password_hash" in updates:
        # credential changed: every existing session for this user is now stale
        owctl.execute("DELETE FROM sessions WHERE user_id=?", (uid,))
    if updates.get("enabled") == 0:
        # disabled account: drop its live sessions too
        owctl.execute("DELETE FROM sessions WHERE user_id=?", (uid,))
    return {"ok": True}


@owctl.app.delete("/api/users/{uid}")
def users_delete(uid: int):
    # Never allow deleting the last enabled admin: that would silently re-seed
    # a passwordless 'admin' on next boot (first-boot seeding fires when the
    # users table is empty), i.e. an accidental lockout/reset of all access.
    victim = owctl._user_by_id(uid)
    if victim is None:
        raise HTTPException(status_code=404, detail="user not found")
    if victim["role"] == "admin" and victim["enabled"]:
        rows = owctl.q("SELECT id FROM users WHERE role='admin' AND enabled=1")
        if len(rows) <= 1:
            raise HTTPException(400, detail="cannot delete the last enabled admin")
    owctl.execute("DELETE FROM sessions WHERE user_id=?", (uid,))
    owctl.execute("DELETE FROM users WHERE id=?", (uid,))
    return {"ok": True}


@owctl.app.get("/api/auth/me")
def auth_me(request: Request):
    """Who is the caller (resolved from the bearer token). Read-only; the
    middleware already rejected unauthenticated /api/ requests, so a valid
    session is guaranteed here. Returns {username, role, id} or 401."""
    auth = request.headers.get("authorization", "").split(" ", 1)
    if len(auth) == 2 and auth[0].lower() == "bearer":
        u = owctl._session_user(auth[1].strip())
        if u:
            return {"username": u["username"], "role": u["role"], "id": u["id"]}
    raise HTTPException(401, "no valid session")


@owctl.app.post("/api/users/me/password-change")
async def users_me_password_change(request: Request):
    """Self-service password change for the currently authenticated user.
    
    Body: {current_password, new_password}
    Resolves caller from bearer token (NOT from body id).
    Verifies current_password matches stored hash.
    Requires new_password length >= 4.
    Updates only that caller's password.
    """
    # Extract bearer token
    auth = request.headers.get("authorization", "").split(" ", 1)
    if len(auth) != 2 or auth[0].lower() != "bearer":
        raise HTTPException(status_code=401, detail="missing bearer token")
    token = auth[1].strip()
    
    # Resolve caller from session
    caller = owctl._session_user(token)
    if not caller:
        raise HTTPException(status_code=401, detail="invalid or expired session")
    if not caller["enabled"]:
        raise HTTPException(status_code=403, detail="account disabled")
    
    # Parse body
    try:
        d = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="invalid JSON body")
    
    current_password = (d.get("current_password") or "").strip()
    new_password = (d.get("new_password") or "").strip()
    
    if not current_password:
        raise HTTPException(status_code=400, detail="current_password required")
    if not new_password:
        raise HTTPException(status_code=400, detail="new_password required")
    
    err = owctl._password_policy_error(new_password)
    if err:
        raise HTTPException(status_code=400, detail=err)
    
    # Verify current password
    if not caller.get("password_hash") or not owctl._verify_password(current_password, caller["password_hash"]):
        raise HTTPException(status_code=400, detail="current password is incorrect")
    
    # Validate new password length
    if len(new_password) < 4:
        raise HTTPException(status_code=400, detail="new password must be at least 4 characters")
    
    # Update the caller's password — and kill every session for this user so
    # an old token cannot survive a credential change (login + self-change +
    # admin reset all invalidate sessions now).
    new_hash = owctl._hash_password(new_password)
    owctl.execute("UPDATE users SET password_hash=? WHERE id=?", (new_hash, caller["id"]))
    owctl.execute("DELETE FROM sessions WHERE user_id=?", (caller["id"],))

    return {"ok": True, "relogin_required": True}


@owctl.app.put("/api/settings")
async def settings_put(request: Request):
    d = await request.json()
    if "audit_interval_min" in d:
        owctl.set_setting("audit_interval_min", str(int(d["audit_interval_min"])))
    if "admin_password" in d and d["admin_password"]:
        ap_err = owctl._password_policy_error(str(d["admin_password"]))
        if ap_err:
            raise HTTPException(400, ap_err)
        owctl.set_setting("admin_password_hash", owctl._hash_password(d["admin_password"]))
        # credential changed: every session for every admin is now stale
        for _r in owctl.q("SELECT id FROM users WHERE role='admin'"):
            owctl.execute("DELETE FROM sessions WHERE user_id=?", (_r["id"],))
    if "network_gateway" in d:
        v = d["network_gateway"]
        if v in (None, ""):
            owctl.set_setting("network_gateway", "")
        else:
            try:
                owctl.set_setting("network_gateway", str(int(v)))
            except (TypeError, ValueError):
                owctl.set_setting("network_gateway", "")
    if "digest_schedule" in d:
        v = str(d.get("digest_schedule") or "").strip().lower()
        if v and v not in owctl._DIGEST_CADENCES:
            raise HTTPException(400, f"invalid digest_schedule: {d.get('digest_schedule')!r} (expected daily|weekly|never)")
        owctl.set_setting("digest_schedule", v or "never")
    return {"ok": True}


@owctl.app.get("/api/audit/api")
def api_audit(limit: int = 100):
    """Recent mutating API requests (who/when/what/result), newest first."""
    limit = max(1, min(500, limit))
    rows = owctl.q("SELECT ts, method, path, client, status FROM api_audit ORDER BY id DESC LIMIT ?", (limit,))
    return {"entries": [dict(r) for r in rows]}


@owctl.app.get("/api/devices/{did}/heartbeat")
def get_device_heartbeat(did: int, limit: int = 200):
    """Return recent heartbeat rows for a device (newest first)."""
    rows = owctl.q("SELECT ts, online FROM device_heartbeats WHERE device_id=? "
             "ORDER BY ts DESC, id DESC LIMIT ?", (did, max(1, min(1000, limit))))
    return [{"ts": r["ts"], "online": bool(r["online"])} for r in rows]


@owctl.app.get("/api/uptime")
def get_uptime():
    """Per-device uptime summary: total checks, online count, uptime %, last seen."""
    rows = owctl.q("""SELECT d.id, d.name, d.host, d.status AS device_status,
                      COUNT(h.id) AS total_checks,
                      SUM(CASE WHEN h.online=1 THEN 1 ELSE 0 END) AS online_count,
                      MAX(h.ts) AS last_seen,
                      MAX(CASE WHEN h.online=1 THEN h.ts END) AS last_online
               FROM devices d
               LEFT JOIN device_heartbeats h ON h.device_id = d.id
               GROUP BY d.id
               ORDER BY d.id""")
    out = []
    for r in rows:
        total = r["total_checks"] or 0
        online = r["online_count"] or 0
        pct = round(100.0 * online / total, 1) if total else None
        out.append({
            "id": r["id"],
            "name": r["name"],
            "host": r["host"],
            "status": r["device_status"],
            "total_checks": total,
            "online_count": online,
            "uptime_pct": pct,
            "last_seen": r["last_seen"],
            "last_online": r["last_online"],
        })
    return out


@owctl.app.get("/api/offline-events")
def get_offline_events(limit: int = 100):
    """Return offline events (newest first)."""
    rows = owctl.q("SELECT * FROM offline_events ORDER BY went_offline DESC, id DESC LIMIT ?",
             (max(1, min(500, limit)),))
    return [dict(r) for r in rows]


@owctl.app.get("/api/dyndns")
def dyndns_read():
    """All DDNS entries (tokens never returned) + the selectable provider list."""
    rows = owctl.q("""SELECT dyndns.id, dyndns.device_id, d.name AS device_name, dyndns.provider,
                       dyndns.hostname, dyndns.enabled, dyndns.last_ip,
                       dyndns.last_update, dyndns.last_result
                FROM dyndns JOIN devices d ON d.id = dyndns.device_id
                ORDER BY d.name, dyndns.provider, dyndns.hostname""")
    return {"providers": sorted(owctl.DDNS_PROVIDERS),
            "entries": [dict(r) for r in rows]}


@owctl.app.post("/api/dyndns")
async def dyndns_create(request: Request):
    """Create/update one DDNS entry.

    payload: {device_id, provider, hostname, token?, extra? (JSON for
    zone/rec/dom), enabled?}. If the device is SSH-accessible, the provider's
    opkg package is installed when missing (idempotent)."""
    d = await request.json()
    # Toggle path: {id, enabled} — no provider/hostname needed.
    if d.get("id") and "enabled" in d and not d.get("provider"):
        row = owctl.q("SELECT * FROM dyndns WHERE id=?", (int(d["id"]),))
        if not row:
            raise HTTPException(404, "entry not found")
        owctl.execute("UPDATE dyndns SET enabled=? WHERE id=?",
                (1 if d["enabled"] else 0, int(d["id"])))
        return {"ok": True, "enabled": bool(d["enabled"])}
    did = int(d.get("device_id") or 0)
    provider = (d.get("provider") or "").strip()
    hostname = (d.get("hostname") or "").strip()
    if not did or provider not in owctl.DDNS_PROVIDERS:
        raise HTTPException(400, "device_id and a known provider required")
    if not hostname:
        raise HTTPException(400, "hostname required")
    cur = owctl.q("SELECT * FROM devices WHERE id=?", (did,))
    if not cur:
        raise HTTPException(404, "device not found")
    dev = cur[0]
    owctl.execute("""INSERT INTO dyndns(device_id, provider, hostname, token, extra, enabled)
               VALUES(?,?,?,?,?,?)
               ON CONFLICT(device_id, provider, hostname) DO UPDATE SET
                 token=excluded.token, extra=excluded.extra, enabled=excluded.enabled""",
            (did, provider, hostname, d.get("token") or "",
             json.dumps(d.get("extra") or {}),
             1 if d.get("enabled", True) else 0))
    installed = owctl._dyndns_ensure_pkg(dev, provider)
    owctl.log_action(dev, "dyndns", f"config {provider} {hostname}", ok=True,
               error=f"pkg install failed: {installed}" if isinstance(installed, str) and installed.startswith("FAIL") else "")
    return {"ok": True, "installed": installed}


@owctl.app.delete("/api/dyndns/{eid}")
def dyndns_delete(eid: int):
    row = owctl.q("SELECT * FROM dyndns WHERE id=?", (eid,))
    if not row:
        raise HTTPException(404, "entry not found")
    r = row[0]
    dev = owctl.q("SELECT * FROM devices WHERE id=?", (r["device_id"],))
    owctl.execute("DELETE FROM dyndns WHERE id=?", (eid,))
    removed = owctl._dyndns_maybe_remove_pkg(dev, r["provider"]) if dev else None
    owctl.log_action(dev[0] if dev else {"id": None, "name": "?"}, "dyndns",
               f"delete {r['provider']} {r['hostname']}", ok=True)
    return {"ok": True, "removed": removed}


@owctl.app.post("/api/dyndns/{eid}/force")
def dyndns_force(eid: int):
    """Gather the device now and push this entry's update immediately."""
    row = owctl.q("SELECT * FROM dyndns WHERE id=?", (eid,))
    if not row:
        raise HTTPException(404, "entry not found")
    dev = owctl.q("SELECT * FROM devices WHERE id=?", (row[0]["device_id"],))
    if not dev:
        raise HTTPException(404, "device not found")
    try:
        st = owctl.dyndns_update_device(dev[0])
    except Exception as e:
        raise HTTPException(502, owctl.enrich_device_error(dev[0], str(e), "dyndns_force"))
    after = owctl.q("SELECT last_ip, last_update, last_result FROM dyndns WHERE id=?", (eid,))
    return {"ok": True, "wan_ip": st.get("wan_ip"), **after[0]}
