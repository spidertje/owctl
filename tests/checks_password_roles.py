#!/usr/bin/env python3
"""checks_password_roles.py — the password-change endpoint must work for EVERY
logged-in role (self-service), enforced by the REAL role middleware.

Unlike checks_password_change.py, this harness does NOT set OWCTL_ALLOW_OPEN=1,
so the token_guard middleware's admin/observer allowlist is exercised for real:
an observer changing their OWN password must be allowed (200), while an
observer is still denied a genuinely admin-only mutation (403).
"""
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ["OWCTL_DATA"] = "/tmp/owctl-pwroles-test-" + str(os.getpid())
os.makedirs(os.environ["OWCTL_DATA"], exist_ok=True)
# NOTE: OWCTL_ALLOW_OPEN deliberately NOT set -> the role middleware is live.

import owctl  # noqa
from starlette.testclient import TestClient

client = TestClient(owctl.app)
FAILS = []


def check(name, cond, extra=""):
    ok = bool(cond)
    print(("ok   " if ok else "FAIL ") + name + (f"  {extra}" if (extra and not ok) else ""))
    if not ok:
        FAILS.append(name)


owctl.init_db()

# Seed an observer + an admin with known passwords.
owctl.execute(
    "INSERT INTO users(username, password_hash, role, enabled, created_at) VALUES(?,?,?,?,?)",
    ("obs", owctl._hash_password("obs-pw-123"), "observer", 1, owctl.now()))
owctl.execute(
    "INSERT INTO users(username, password_hash, role, enabled, created_at) VALUES(?,?,?,?,?)",
    ("adm", owctl._hash_password("adm-pw-123"), "admin", 1, owctl.now()))

# --- Observer self-service: change their OWN password ---
r = client.post("/api/auth/login", json={"username": "obs", "password": "obs-pw-123"})
check("observer login -> 200", r.status_code == 200, f"{r.status_code} {r.text}")
obs_tok = (r.json() or {}).get("session", "")
H_obs = {"Authorization": "Bearer " + obs_tok}

r = client.post("/api/users/me/password-change",
                json={"current_password": "obs-pw-123", "new_password": "obs-new-456"},
                headers=H_obs)
check("observer changes OWN password -> 200", r.status_code == 200, f"{r.status_code} {r.text}")

r = client.post("/api/auth/login", json={"username": "obs", "password": "obs-new-456"})
check("observer login with NEW password -> 200", r.status_code == 200, f"{r.status_code}")
r = client.post("/api/auth/login", json={"username": "obs", "password": "obs-pw-123"})
check("observer login with OLD password -> 401", r.status_code == 401, f"{r.status_code}")

# The fix ALSO killed the caller's live session (password-change rotates
# sessions): the old token must now be rejected. Then re-login to keep
# exercising role enforcement with a fresh token.
r = client.get("/api/devices", headers=H_obs)
check("old session dead after own password change -> 401", r.status_code == 401, f"{r.status_code}")
r = client.post("/api/auth/login", json={"username": "obs", "password": "obs-new-456"})
check("observer re-login with NEW password -> 200", r.status_code == 200, f"{r.status_code}")
H_obs = {"Authorization": "Bearer " + (r.json() or {}).get("session", "")}

# --- Observer is still DENIED a genuinely admin-only mutation ---
r = client.post("/api/bulk", json={"action": "check", "devices": []}, headers=H_obs)
check("observer denied admin-only /api/bulk -> 403", r.status_code == 403, f"{r.status_code}")

# --- Admin self-service still works too ---
r = client.post("/api/auth/login", json={"username": "adm", "password": "adm-pw-123"})
adm_tok = (r.json() or {}).get("session", "")
r = client.post("/api/users/me/password-change",
                json={"current_password": "adm-pw-123", "new_password": "adm-new-456"},
                headers={"Authorization": "Bearer " + adm_tok})
check("admin changes OWN password -> 200", r.status_code == 200, f"{r.status_code} {r.text}")

# --- Unauthenticated still 401 ---
r = client.post("/api/users/me/password-change",
                json={"current_password": "x", "new_password": "y"})
check("no token -> 401", r.status_code == 401, f"{r.status_code}")

print()
if FAILS:
    print(f"FAILED: {len(FAILS)} check(s)")
    for f in FAILS:
        print("  - " + f)
    sys.exit(1)
print("ALL PASSWORD-ROLE CHECKS PASSED")
