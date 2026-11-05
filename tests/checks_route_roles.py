#!/usr/bin/env python3
"""checks_route_roles.py — every mutating API route must be explicitly
categorized as admin-only or observer-allowed (audit info finding 2026-11).

Enforces the invariant behind _ADMIN_ONLY_PATHS/_OBSERVER_OK_POST:
1. enumerate all mutating routes registered on owctl.app
2. each must appear in one of the two lists (exact path or {param} form)
3. observer sessions get 403 on a sample of newly-categorized paths
"""
import os, sys, re
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ["OWCTL_DATA"] = "/tmp/owctl-routeroles-" + str(os.getpid())
os.environ["OWCTL_ALLOW_OPEN"] = "0"
os.makedirs(os.environ["OWCTL_DATA"], exist_ok=True)
import owctl
import owctl.auth as A
from starlette.testclient import TestClient
client = TestClient(owctl.app)

passed = failed = 0
def check(name, cond):
    global passed, failed
    if cond: passed += 1; print("PASS", name)
    else: failed += 1; print("FAIL", name)

owctl.init_db()

# 1. completeness: every mutating route is categorized
from starlette.routing import Route
mut = set()
for r in owctl.app.routes:
    if isinstance(r, Route):
        for m in r.methods:
            if m in ("POST", "PUT", "DELETE", "PATCH"):
                mut.add(r.path)
admin = set(A._ADMIN_ONLY_PATHS)
obs = set(A._OBSERVER_OK_POST)
auth_public = {p for p in mut if p.startswith("/api/auth")}
# /api/users/me/password-change is intentionally allowed for observers
unclass = sorted(p for p in mut
                 if p not in admin and p not in obs and p not in auth_public
                 and not p.startswith("/api/users/me"))
check("no uncategorized mutating routes", not unclass)
if unclass:
    print("  unclassified:", unclass)
check("lists cover all mutating routes", len(mut) <= len(admin) + len(obs) + len(auth_public) + 1)

# 2. behavioral spot-check: observer gets 403 on newly-explicit paths
owctl.execute("INSERT INTO users(username,password_hash,role,enabled,created_at) VALUES('rr_admin',?,'admin',1,?)",
              (owctl._hash_password("rr-admin-123"), owctl.now()))
owctl.execute("INSERT INTO users(username,password_hash,role,enabled,created_at) VALUES('rr_obs',?,'observer',1,?)",
              (owctl._hash_password("rr-obs-123"), owctl.now()))
tok = client.post("/api/auth/login", json={"username": "rr_admin", "password": "rr-admin-123"}).json()["session"]
H = {"Authorization": "Bearer" + " " + tok}
uid = owctl.q("SELECT id FROM users WHERE username='rr_obs'")[0]["id"]

obs_tok = client.post("/api/auth/login", json={"username": "rr_obs", "password": "rr-obs-123"}).json()["session"]
OH = {"Authorization": "Bearer" + " " + obs_tok}
# sample newly-categorized paths: user CRUD, dyndns, vlans delete, switch-ports, firewall rule
did = owctl.execute("INSERT INTO devices(name,host,access,role,added_at) VALUES('rr','10.99.0.1','ssh','switch',?)", (owctl.now(),))
for label, method, path in [
    ("POST /api/users", "POST", "/api/users"),
    ("DELETE /api/users/{uid}", "DELETE", f"/api/users/{uid}"),
    ("POST /api/dyndns", "POST", "/api/dyndns"),
    ("POST /api/vlans/delete", "POST", "/api/vlans/delete"),
    ("POST switch-ports", "POST", f"/api/devices/{did}/switch-ports"),
    ("PUT firewall rule", "PUT", "/api/firewall/1/rule/x%20"),
]:
    r = client.request(method, path, json={}, headers=OH)
    check(f"observer 403: {label}", r.status_code == 403)
# admin still ALLOWED on the same paths (not over-blocking): bad-request past the gate, not 403
r = client.request("POST", "/api/vlans/delete", json={"vlan_id": 0}, headers=H)
check("admin not 403 on vlans/delete", r.status_code != 403)
r = client.request("DELETE", f"/api/users/{owctl.q('SELECT id FROM users WHERE username=\"rr_obs\"')[0]['id']}", json={}, headers=H)
check("admin not 403 on users delete", r.status_code in (200, 400))

# 3. regex form: the {param} entries actually match concrete requests
check("_ADMIN_ONLY_RE matches concrete /api/users/5",
      any(rx.match("/api/users/5") for rx in owctl._ADMIN_ONLY_RE))
check("_ADMIN_ONLY_RE matches concrete firewall rule path",
      any(rx.match("/api/firewall/7/rule/myrule") for rx in owctl._ADMIN_ONLY_RE))
check("_ADMIN_ONLY_RE matches concrete dyndns force",
      any(rx.match("/api/dyndns/3/force") for rx in owctl._ADMIN_ONLY_RE))
# _normalize_path regression: placeholders substituted BEFORE escaping.
# Escaping first emitted '\\{' so the substitution never saw the placeholder
# and every parameterized entry silently failed to match.
check("_normalize_path placeholder becomes char-class",
        owctl._normalize_path("/api/devices/{did}/check") == r"/api/devices/[^/]+/check$")
check("_normalize_path regex actually matches",
        bool(re.match(owctl._normalize_path("/api/devices/{did}/check"), "/api/devices/12/check")))
check("observer-allowed parameterized path matches",
        any(rx.match("/api/devices/42/check") for rx in owctl._OBSERVER_OK_RE))
check("observer-allowed parameterized path matches test",
        any(rx.match("/api/devices/42/test") for rx in owctl._OBSERVER_OK_RE))
check("regex is anchored (no prefix match)",
        not any(rx.match("/api/users/5/extra") for rx in owctl._ADMIN_ONLY_RE))

print(f"\n=== SUMMARY ===\n{passed}/{passed+failed} checks passed")
import sys as _s; _s.exit(1 if failed else 0)
