"""owctl.auth"""
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

_ROLES = {"admin", "observer"}


_SESSION_TTL = 86400  # 24h


_OBSERVER_OK_POST = {
    "/api/devices/{did}/check", "/api/devices/{did}/test",
    "/api/devices/{did}/heartbeat", "/api/sweep",
    # self-service: a logged-in user changes their OWN password (resolved from
    # the bearer token, never another account) — allowed for every role.
    "/api/users/me/password-change",
}


_ADMIN_ONLY_PATHS = {
    "/api/devices", "/api/devices/{did}", "/api/devices/{did}/backup",
    "/api/devices/{did}/restore", "/api/devices/{did}/reboot",
    "/api/devices/{did}/upgrade", "/api/devices/{did}/push-key",
    "/api/fleet/upgrade", "/api/rebaseline/apply",
    "/api/devices/{did}/guest-wifi", "/api/devices/{did}/wifi-clone",
    "/api/dhcp/apply", "/api/dns/apply", "/api/firewall/apply",
    "/api/qos/apply", "/api/vlans/apply", "/api/vlans/discover",
    "/api/devices/{did}/pending-apply",
    "/api/alerts/config", "/api/bulk", "/api/digest",
    "/api/findings/ack", "/api/settings", "/api/backup",
    # routing (logical network object): per-device + fleet mutations
    "/api/devices/{did}/routes", "/api/devices/{did}/routes/delete",
    "/api/devices/{did}/policy-routes", "/api/devices/{did}/bgp",
    "/api/routes/apply", "/api/routes/delete",
    # Explicitly categorized 2026-11-05 (audit info finding): every mutating
    # route is now listed here OR in _OBSERVER_OK_POST — token_guard's
    # deny-by-default still protects, but an explicit list is auditable and
    # survives future middleware refactors. tests/checks_route_roles.py
    # fails if a mutating route is ever added without being categorized.
    "/api/devices/{did}/mesh", "/api/devices/{did}/packages/remove",
    "/api/devices/{did}/switch-ports",
    "/api/dhcp/reserve", "/api/vlans/delete", "/api/pending/apply",
    "/api/dyndns", "/api/dyndns/{eid}", "/api/dyndns/{eid}/force",
    "/api/firewall/{did}/rule/{name}", "/api/firewall/{did}/forward/{name}",
    "/api/users", "/api/users/{uid}",
}


def _hash_password(password: str) -> str:
    # bcrypt silently truncates input at 72 bytes; callers must reject longer
    # passwords instead (see _password_policy_error).
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12)).decode()


def _password_policy_error(password: str):
    """Return a 400-detail string when a password violates policy, else None.

    - min 4 chars (matches setup/change/create/dashboard)
    - bcrypt truncates at 72 bytes, so cap explicitly rather than silently
      hashing a truncated secret.
    """
    if len(password) < 4:
        return "password must be at least 4 characters"
    if len(password.encode("utf-8")) > 72:
        return "password must be at most 72 bytes (UTF-8)"
    return None


def _verify_password(password: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode(), hashed.encode())
    except Exception:
        return False


def ensure_admin_password():
    """Return the stored admin password hash, or None if none is set yet."""
    return (owctl.get_setting("admin_password_hash", "") or "").strip() or None


def _user_by_id(uid):
    rows = owctl.q("SELECT * FROM users WHERE id=?", (uid,))
    return rows[0] if rows else None


def _user_by_username(username):
    rows = owctl.q("SELECT * FROM users WHERE username=?", (username,))
    return rows[0] if rows else None


def _create_session(user_id: int) -> str:
    tok = secrets.token_hex(32)
    now = time.time()
    owctl.execute("INSERT INTO sessions(token, user_id, created, exp) VALUES(?,?,?,?)",
            (tok, user_id, now, now + _SESSION_TTL))
    # Keep the table bounded — evict anything older than 2x TTL.
    owctl.execute("DELETE FROM sessions WHERE exp < ?", (now - _SESSION_TTL,))
    return tok


def _session_user(token: str):
    if not token:
        return None
    ts = time.time()
    rows = owctl.q("""SELECT u.* FROM sessions s JOIN users u ON u.id=s.user_id
               WHERE s.token=? AND s.exp>? AND u.enabled=1""",
             (token, ts))
    if rows:
        owctl.execute("UPDATE users SET last_login=? WHERE id=?",
                (owctl.now(), rows[0]["id"]))
        return rows[0]
    owctl.execute("DELETE FROM sessions WHERE token=?", (token,))
    return None


def _purge_expired_sessions():
    owctl.execute("DELETE FROM sessions WHERE exp < ?", (time.time(),))


def _ensure_default_admin():
    """On first boot, no admin exists. Seed one admin account (password set at
    first login) so the system is never left without an admin."""
    if not owctl.q("SELECT 1 FROM users LIMIT 1"):
        owctl.execute("INSERT INTO users(username, password_hash, role, enabled, created_at) "
                "VALUES('admin', ?, 'admin', 1, ?)",
                ("", owctl.now()))


def _normalize_path(pattern):
    """/api/devices/{did} -> regex for /api/devices/123.

    The {param} placeholders are substituted BEFORE escaping the rest —
    re.escape('{') emits '\\{' which the substitution below would never see,
    so escaping-first-then-substituting silently broke every parameterized
    entry (observer-allowed /api/devices/{did}/check never matched)."""
    parts = re.split(r"(/\{[^/}]+\})", pattern)
    out = ["/[^/]+" if re.fullmatch(r"/\{[^/}]+\}", p) else re.escape(p)
         for p in parts]
    return "".join(out) + "$"


_ADMIN_ONLY_RE = [re.compile(_normalize_path(p)) for p in _ADMIN_ONLY_PATHS]


_OBSERVER_OK_RE = [re.compile(_normalize_path(p)) for p in _OBSERVER_OK_POST]


def _observer_allowed(path: str, method: str) -> bool:
    if method == "GET":
        return True
    if any(rx.match(path) for rx in _ADMIN_ONLY_RE):
        return False
    return any(rx.match(path) for rx in _OBSERVER_OK_RE)
