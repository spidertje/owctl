"""owctl.dyndns"""
import owctl  # shared namespace (patched names)

import base64, difflib, json, os, re, secrets, smtplib, socket, sqlite3, ssl
import threading, time, logging, sys, ipaddress, paramiko, bcrypt
import urllib.parse, urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from email.message import EmailMessage
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

def _ddns_apply(dev, st):
    """Update every enabled DDNS entry for a device after a gather.

    Runs inside the scheduler and the manual /dyndns/force endpoint. Never
    raises: a failed update records its error in last_result and retries next
    interval. Skips when the WAN IP is empty or unchanged since last update.
    """
    ip = st.get("wan_ip") or ""
    if not ip:
        return
    rows = owctl.q("SELECT * FROM dyndns WHERE device_id=? AND enabled=1", (dev["id"],))
    for r in rows:
        prov = owctl.DDNS_PROVIDERS.get(r["provider"])
        if not prov:
            owctl.execute("UPDATE dyndns SET last_result=? WHERE id=?",
                    (f"unknown provider {r['provider']}", r["id"]))
            continue
        if r["last_ip"] == ip and r["last_result"] and r["last_result"].startswith("ok"):
            continue  # no change, no request
        try:
            host = r["hostname"]
            extra = {}
            if r.get("extra"):
                try:
                    extra = json.loads(r["extra"])
                except Exception:
                    extra = {}
            url = prov["url"].format(host=host, ip=ip,
                                     token=r.get("token") or "",
                                     zone=extra.get("zone") or "",
                                     rec=extra.get("rec") or "",
                                     dom=extra.get("dom") or "")
            req = urllib.request.Request(url, method="POST" if prov.get("json_body") else "GET",
                                         headers={"User-Agent": "owctl-dyndns/1.0"})
            with urllib.request.urlopen(req, timeout=15) as resp:
                body = resp.read().decode(errors="replace").strip().lower()
            ok = prov["ok"].lower() in body
            result = "ok" if ok else f"bad response: {body[:80]}"
        except Exception as e:
            ok = False
            result = f"error: {e}"
            host = r["hostname"]
        owctl.execute("""UPDATE dyndns SET last_ip=?, last_update=?, last_result=?
                   WHERE id=?""", (ip, owctl.now(), result, r["id"]))
        if ok and r["last_ip"] != ip:
            owctl.log_action(dev, "dyndns", f"{r['provider']} {host} -> {ip}", ok=True)


def dyndns_update_device(dev):
    """Gather + update DDNS for one device (manual force / scheduler)."""
    st = owctl.gather(dev)
    owctl.record_heartbeat(dev, True)
    owctl.execute("UPDATE devices SET status='online', last_checked=? WHERE id=?",
            (owctl.now(), dev["id"]))
    _ddns_apply(dev, st)
    return st


def _dyndns_pkg_for(provider: str):
    """opkg package that carries a provider's client, or None for pure-HTTP
    providers (duckdns/dynu/noip/freedns all work from a one-liner curl).
    ponytail: keep the map in sync with DDNS_PROVIDERS; the only providers that
    actually need a package on the box today are cloudflare (its API wants
    signed JSON, so we lean on the cloudflare-ddns client) and ovh."""
    return {"cloudflare": "luci-app-cloudflare-ddns", "ovh": "luci-app-ovhddns"}.get(provider)


def _dyndns_ensure_pkg(dev, provider):
    """Install the provider's opkg package when missing. Returns '' (present /
    not needed) or a FAIL-prefixed string on error. Never raises."""
    pkg = _dyndns_pkg_for(provider)
    if not pkg:
        return ""
    if dev.get("access") != "ssh":
        return f"FAIL(pkg install skipped: no SSH on {dev.get('name')})"
    cmd = (f"opkg list-installed {pkg} >/dev/null 2>&1 && echo present || "
           f"(opkg update && opkg install -y {pkg}) >/dev/null 2>&1 && echo installed")
    try:
        c = owctl._ssh_connect(dev)
        try:
            out, err, status = owctl._exec_capture(c, cmd, timeout=600)
            if status != 0:
                return f"FAIL({(err or out).strip()[:120]})"
            return (out.strip() or "")
        finally:
            c.close()
    except Exception as e:
        return f"FAIL({e})"


def _dyndns_maybe_remove_pkg(dev, provider):
    """Remove the provider's package if this device has no other dyndns rows
    for it. Returns the removed package name, '' when nothing to do, or a
    FAIL string. Never raises."""
    pkg = _dyndns_pkg_for(provider)
    if not pkg or dev[0].get("access") != "ssh":
        return ""
    left = owctl.q("SELECT 1 FROM dyndns WHERE device_id=? AND provider=? LIMIT 1",
             (dev[0]["id"], provider))
    if left:
        return ""
    try:
        owctl._run_ssh(dev[0], f"opkg remove -y {pkg} 2>/dev/null || true", "package_remove",
                 f"dyndns-uninstall {pkg}", "dyndns package removal")
        return pkg
    except Exception as e:
        return f"FAIL({e})"
