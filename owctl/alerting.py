"""owctl.alerting"""
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

DEFAULT_ALERTS = {
    "min_severity": "MEDIUM",
    "channels": {
        "dashboard": True,
        "email": {"enabled": False, "smtp_host": "", "smtp_port": 587, "use_tls": True,
                  "user": "", "password": "", "from": "", "to": ""},
        "telegram": {"enabled": False, "token": "", "chat_id": ""},
        "webhook": {"enabled": False, "url": ""},
        "ntfy": {"enabled": False, "server": "https://ntfy.sh", "topic": ""},
        "pushover": {"enabled": False, "token": "", "user_key": ""},
        "discord": {"enabled": False, "webhook_url": ""},
    },
}


def _chan_fail(name, e):
    """Channel-failure marker for alert_log WITHOUT leaking secrets.

    urllib/SMTP exception strings can embed the full request URL, which for
    these channels contains credentials (telegram bot token in the path,
    webhook/discord URLs are bearer secrets, SMTP errors can echo the host).
    Keep the class name + a redacted message only.
    """
    msg = str(e)
    # belt-and-braces: strip URL userinfo/paths and obvious token shapes
    msg = re.sub(r"https?://[^\s'\"]*", "[url]", msg)
    msg = re.sub(r"[A-Za-z0-9_-]{6,32}:[A-Za-z0-9_-]{20,}", "[cred]", msg)
    return f"{name}:FAIL({type(e).__name__}: {msg[:200]})"


def get_alert_cfg():
    raw = owctl.get_setting("alerts", "")
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
    owctl.set_setting("alerts", json.dumps(cfg))


def fire_alert(dev, finding):
    cfg = get_alert_cfg()
    min_rank = owctl.SEV_RANK.get(cfg.get("min_severity", "MEDIUM"), 2)
    text = f"[{finding['severity']}] {dev['name']} ({dev['host']}): {finding['message']}"
    log_id = owctl.execute("INSERT INTO alert_log(ts, device, severity, rule_id, message, channels) "
                     "VALUES(?,?,?,?,?,?)", (owctl.now(), dev["name"], finding["severity"],
                                             finding["rule_id"], finding["message"], ""))
    used = []
    if owctl.SEV_RANK.get(finding["severity"], 0) < min_rank:
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
            used.append(_chan_fail("email", e))
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
            used.append(_chan_fail("telegram", e))
    wh = ch.get("webhook") or {}
    if wh.get("enabled") and wh.get("url"):
        try:
            payload = json.dumps({"ts": owctl.now(), "device": dev["name"], "host": dev["host"], **finding}).encode()
            req = urllib.request.Request(wh["url"], data=payload,
                                         headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=20) as r:
                r.read()
            used.append("webhook")
        except Exception as e:
            used.append(_chan_fail("webhook", e))
    nf = ch.get("ntfy") or {}
    if nf.get("enabled") and nf.get("topic"):
        try:
            server = (nf.get("server") or "https://ntfy.sh").rstrip("/")
            payload = text.encode()
            req = urllib.request.Request(
                f"{server}/{nf['topic']}", data=payload,
                headers={"Content-Type": "text/plain",
                         "Title": f"owctl [{finding['severity']}] {dev['name']}"})
            with urllib.request.urlopen(req, timeout=20) as r:
                r.read()
            used.append("ntfy")
        except Exception as e:
            used.append(_chan_fail("ntfy", e))
    po = ch.get("pushover") or {}
    if po.get("enabled") and po.get("token") and po.get("user_key"):
        try:
            payload = urllib.parse.urlencode({
                "token": po["token"], "user": po["user_key"],
                "message": text, "title": f"owctl {finding['severity']}"}).encode()
            req = urllib.request.Request(
                "https://api.pushover.net/1/messages.json", data=payload,
                headers={"Content-Type": "application/x-www-form-urlencoded"})
            with urllib.request.urlopen(req, timeout=20) as r:
                r.read()
            used.append("pushover")
        except Exception as e:
            used.append(_chan_fail("pushover", e))
    dc = ch.get("discord") or {}
    if dc.get("enabled") and dc.get("webhook_url") and dc["webhook_url"].startswith("https://"):
        try:
            payload = json.dumps({"content": text}).encode()
            req = urllib.request.Request(
                dc["webhook_url"], data=payload,
                headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=20) as r:
                r.read()
            used.append("discord")
        except Exception as e:
            used.append(_chan_fail("discord", e))
    if used:
        owctl.execute("UPDATE alert_log SET channels=? WHERE id=?", (",".join(used), log_id))
    return used


def build_digest():
    devices = owctl.q("SELECT * FROM devices ORDER BY name")
    if not devices:
        return ("OpenWrt Fleet Digest — no devices registered",
                "No devices are currently registered in owctl.\n")

    lines = []
    for dev in devices:
        lines.append(f"=== {dev['name']} ({dev['host']}) ===")
        lines.append(f"Status: {dev.get('status', 'unknown')}")
        lines.append(f"Health score: {dev.get('health_score', 'N/A')}")
        afs = owctl.q("SELECT severity, message, detail FROM active_findings WHERE device_id=? ORDER BY severity",
                (dev['id'],))
        if afs:
            cnt = {}
            for a in afs:
                cnt[a['severity']] = cnt.get(a['severity'], 0) + 1
            lines.append(f"Active findings: {cnt}")
            for a in afs:
                lines.append(f"  [{a['severity']}] {a['message']}")
                if a.get('detail'):
                    lines.append(f"    {a['detail']}")
        else:
            lines.append("Active findings: none")
        lines.append("")

    new = owctl.q("SELECT ts, device_name, rule_id, severity, message FROM findings WHERE ts > datetime('now', '-7 days') ORDER BY ts DESC")
    lines.append("=== New in last 7 days ===")
    if new:
        for f in new:
            lines.append(f"  [{f['severity']}] {f['device_name']}: {f['message']} ({f['ts']})")
    else:
        lines.append("  No new findings in the last 7 days.")
    lines.append("")

    offline = [d for d in devices if d.get('status') != 'online']
    total_active = sum(len(owctl.q("SELECT 1 FROM active_findings WHERE device_id=?", (d['id'],))) for d in devices)
    lines.append(f"Summary: {len(devices)} device(s), {total_active} active findings, {len(offline)} offline")

    subject = f"OpenWrt Fleet Digest — {len(devices)} device(s), {total_active} findings"
    body = "\n".join(lines) + "\n"
    return subject, body
