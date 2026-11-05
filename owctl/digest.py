"""owctl.digest"""
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

_DIGEST_CADENCES = {"daily", "weekly", "never"}


def digest_schedule() -> str:
    """Return the validated cadence ('daily'|'weekly'|'never').

    Invalid/missing values fall back to 'never' — a typo never schedules an
    unexpected run, and the GET /api/settings always returns a known value.
    """
    v = (owctl.get_setting("digest_schedule", "never") or "never").strip().lower()
    if v not in _DIGEST_CADENCES:
        return "never"
    return v


def digest_should_fire(cadence, last_sent_ts, now_ts=None) -> bool:
    """Pure decision: should the digest fire now?

    cadence:     'daily' | 'weekly' | 'never'
    last_sent_ts: epoch seconds of the last successful send (0 = never sent)
    now_ts:       epoch seconds of 'now' (default time.time(); injectable so
                  the cadence logic is unit-testable without touching the clock)

    'daily'  = at least 24h since the last send.
    'weekly' = at least 7 days since the last send.
    Boundary (exactly the interval) fires — consistent with the old weekly
    trigger that compared against 7 * 24 * 3600.
    """
    if cadence not in _DIGEST_CADENCES or cadence == "never":
        return False
    now_ts = time.time() if now_ts is None else float(now_ts)
    last_sent_ts = float(last_sent_ts or 0)
    interval = 24 * 3600 if cadence == "daily" else 7 * 24 * 3600
    return now_ts - last_sent_ts >= interval


def send_digest():
    cfg = owctl.get_alert_cfg()
    ch = (cfg.get("channels") or {}).get("email") or {}
    if not ch.get("enabled") or not ch.get("to") or not ch.get("smtp_host"):
        return {"sent": False, "reason": "email channel not configured"}
    try:
        subject, body = owctl.build_digest()
    except Exception as e:
        return {"sent": False, "reason": f"build_digest: {e}"}
    try:
        msg = EmailMessage()
        msg["Subject"] = subject
        msg["From"] = ch.get("from") or ch.get("user") or "owctl@lan"
        msg["To"] = ch["to"]
        msg.set_content(body)
        with smtplib.SMTP(ch["smtp_host"], int(ch.get("smtp_port") or 587), timeout=20) as s:
            if ch.get("use_tls", True):
                s.starttls()
            if ch.get("user"):
                s.login(ch["user"], ch.get("password", ""))
            s.send_message(msg)
        return {"sent": True, "to": ch["to"]}
    except Exception as e:
        return {"sent": False, "reason": str(e)}
