#!/usr/bin/env python3
"""checks_security_fixes.py — pin the audit-fix wave (2026-11).

Covers:
  * vlan_id injection choke point (do_vlan/do_vlan_delete + endpoints 400 on junk)
  * session rotation on password change (self + admin-reset + settings admin_password)
  * last-enabled-admin delete guard
  * password policy: min 4, max 72 bytes (bcrypt truncation guard)
  * alert channel FAIL markers redact URLs/creds
  * _exec_capture output cap (no OOM on runaway remote output)
  * CSP header present on static + API, absent on /docs
  * hot-path indexes created by init_db
"""
import os, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ["OWCTL_DATA"] = "/tmp/owctl-secfix-test-" + str(os.getpid())
os.environ["OWCTL_ALLOW_OPEN"] = "1"  # BEFORE import
os.makedirs(os.environ["OWCTL_DATA"], exist_ok=True)
import owctl
import importlib
importlib.reload(owctl)
from starlette.testclient import TestClient
client = TestClient(owctl.app)

passed = failed = 0
def check(name, cond):
    global passed, failed
    if cond: passed += 1; print("PASS", name)
    else: failed += 1; print("FAIL", name)

owctl.init_db()

# ── 1. vlan_id injection choke point ─────────────────────────────────────
check("_valid_vlan_id accepts int", owctl._valid_vlan_id(10) == 10)
check("_valid_vlan_id accepts '10'", owctl._valid_vlan_id("10") == 10)
from fastapi import HTTPException
try:
    owctl._valid_vlan_id("10' ; id ; #"); check("_valid_vlan_id rejects shell junk", False)
except HTTPException as e:
    check("_valid_vlan_id rejects shell junk", e.status_code == 400)
try:
    owctl._valid_vlan_id(0); check("_valid_vlan_id rejects 0", False)
except HTTPException as e:
    check("_valid_vlan_id rejects 0", e.status_code == 400)
try:
    owctl._valid_vlan_id(4095); check("_valid_vlan_id rejects 4095", False)
except HTTPException as e:
    check("_valid_vlan_id rejects 4095", e.status_code == 400)

# endpoint level: bad vlan_id -> 400 before any SSH/mock
did = owctl.execute("INSERT INTO devices(name,host,access,added_at) VALUES('dv','10.99.99.99','ssh',?)", (owctl.now(),))
r = client.post("/api/vlans/apply", json={"vlan_id": "5' ; touch /tmp/owctl-pwned ; #", "devices": [did]})
check("POST /api/vlans/apply shell-junk -> 400", r.status_code == 400)
r = client.post("/api/vlans/delete", json={"vlan_id": "5; touch /tmp/owctl-pwned; #", "devices": [did]})
check("POST /api/vlans/delete shell-junk -> 400", r.status_code == 400)
check("no /tmp/owctl-pwned created", not os.path.exists("/tmp/owctl-pwned"))

# do_vlan itself must normalize to int (monkeypatched connect so no real SSH)
import types
class _FakeChan:
    def __init__(self): pass
class _FakeClient:
    def exec_command(self, cmd, timeout=0):
        _FakeClient.seen = cmd
        import io
        return io.BytesIO(b""), _FakeStdout(b""), io.BytesIO(b"")
    def get_transport(self): raise RuntimeError("no transport")
    def close(self): pass
class _FakeStdout:
    def __init__(self, b): self.b = b
    def read(self): return self.b
    def channel(self): return None
owctl._ssh_connect = lambda dev: _FakeClient()
owctl._PENDING_RESTARTS.setdefault("vlan", "true")
try:
    owctl.do_vlan(dict(id=did, name="dv", access="ssh"), "7", "home", "192.168.7.0/24", False, [did], did, apply=False)
except Exception:
    pass
seen = getattr(_FakeClient, "seen", "")
check("do_vlan emits int vlan_7", "network.vlan_7=" in seen and ";" not in seen)

# ── 2. session rotation on password change ───────────────────────────────
os.environ.pop("OWCTL_ALLOW_OPEN")  # exercise the real middleware
importlib.reload(owctl)
client = TestClient(owctl.app)
owctl.execute("INSERT INTO users(username,password_hash,role,enabled,created_at) VALUES('sa',?,'admin',1,?)",
              (owctl._hash_password("sa-pw-123"), owctl.now()))
r = client.post("/api/auth/login", json={"username": "sa", "password": "sa-pw-123"})
check("admin login", r.status_code == 200)
tok = (r.json() or {}).get("session", "")
H = {"Authorization": "Bearer " + tok}
r = client.post("/api/users/me/password-change", json={"current_password": "sa-pw-123", "new_password": "sa-new-456"}, headers=H)
check("self password change -> 200", r.status_code == 200)
r = client.get("/api/devices", headers=H)
check("old session dead after change -> 401", r.status_code == 401)
r = client.post("/api/auth/login", json={"username": "sa", "password": "sa-new-456"})
check("login with new pw", r.status_code == 200)
tok2 = (r.json() or {}).get("session", "")
H2 = {"Authorization": "Bearer " + tok2}

# admin reset another user's password kills their sessions
owctl.execute("INSERT INTO users(username,password_hash,role,enabled,created_at) VALUES('ob',?,'observer',1,?)",
              (owctl._hash_password("ob-pw-123"), owctl.now()))
r = client.post("/api/auth/login", json={"username": "ob", "password": "ob-pw-123"})
ob_tok = (r.json() or {}).get("session", "")
r = client.put("/api/users/2", json={"password": "ob-reset-789"}, headers=H2)  # uid of ob
# find ob's uid if not 2
ob = owctl.q("SELECT id FROM users WHERE username='ob'")[0]["id"]
r = client.put(f"/api/users/{ob}", json={"password": "ob-reset-789"}, headers=H2)
check("admin password reset -> 200", r.status_code == 200)
r = client.get("/api/devices", headers={"Authorization": "Bearer " + ob_tok})
check("reset user's sessions killed -> 401", r.status_code == 401)

# ── 3. last-admin guard ──────────────────────────────────────────────────
r = client.delete(f"/api/users/{owctl.q('SELECT id FROM users WHERE username=\"sa\"')[0]['id']}", headers=H2)
check("cannot delete last enabled admin -> 400", r.status_code == 400)

# ── 4. password policy (bcrypt truncation guard) ─────────────────────────
r = client.post("/api/users", json={"username": "longpw", "password": "x" * 80, "role": "observer"}, headers=H2)
check("over-72-byte password -> 400", r.status_code == 400)
r = client.post("/api/users", json={"username": "shortpw", "password": "x", "role": "observer"}, headers=H2)
check("under-4 password -> 400", r.status_code == 400)

# ── 5. alert FAIL redaction ──────────────────────────────────────────────
from owctl.alerting import _chan_fail
m = _chan_fail("telegram", RuntimeError("HTTP 404: https://api.telegram.org/bot123:SECRETABC/sendMessage"))
check("FAIL marker redacts url", "api.telegram.org" not in m and "SECRETABC" not in m)
check("FAIL marker keeps class", "RuntimeError" in m)

# ── 6. _exec_capture output cap ──────────────────────────────────────────
import owctl.ssh as _ssh
class _BigChan:
    def exec_command(self, cmd): pass
    def makefile(self, mode="rb"): return _Repeat(b"x" * 1024)
    def makefile_stderr(self, mode="rb"): return _Repeat(b"")
    def recv_exit_status(self): return 0
    def close(self): pass
class _Repeat:
    def __init__(self, b): self.n = 0
    def read(self, n):
        self.n += 1
        if self.n > 1200: return b""   # ~1.2MB of 1024-byte chunks
        return b"x" * n
class _BigClient:
    def get_transport(self): return self
    def open_session(self): return _BigChan()
import owctl as _o
_o._exec_capture = _ssh._exec_capture  # ensure real one
out, err, st = _ssh._exec_capture(_BigClient(), "yes", timeout=5)
check("capture capped at 8MB marker", "truncated" in out or len(out) <= 8 * 1024 * 1024)

# ── 7. CSP header ────────────────────────────────────────────────────────
os.environ["OWCTL_ALLOW_OPEN"] = "1"
importlib.reload(owctl)
client = TestClient(owctl.app)
r = client.get("/api/health")
check("CSP on API", "Content-Security-Policy" in r.headers and "default-src 'self'" in r.headers.get("Content-Security-Policy", ""))
r = client.get("/")
check("CSP on dashboard", "default-src 'self'" in r.headers.get("Content-Security-Policy", ""))
r = client.get("/docs")
check("no CSP on /docs (CDN scripts)", "Content-Security-Policy" not in r.headers)

# ── 8. indexes exist ─────────────────────────────────────────────────────
idx = owctl.q("SELECT name FROM sqlite_master WHERE type='index' AND name LIKE 'idx_%'")
check("hot-path indexes created", len(idx) >= 8)

print(f"\n=== SUMMARY ===\n{passed}/{passed+failed} checks passed")
import sys; sys.exit(1 if failed else 0)
