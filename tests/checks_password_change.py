#!/usr/bin/env python3
"""checks_password_change.py — verify self-service password change endpoint."""

import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# (a) import owctl with a temp OWCTL_DATA so we never touch the real DB
tmp = tempfile.mkdtemp()
os.environ["OWCTL_DATA"] = tmp
os.environ["OWCTL_ALLOW_OPEN"] = "1"

import owctl  # noqa: E402
from starlette.testclient import TestClient

client = TestClient(owctl.app)
CHECKS = []


def check(name, cond, extra=""):
    CHECKS.append((name, bool(cond), extra))
    print(("PASS " if cond else "FAIL ") + name + (f"  [{extra}]" if extra and not cond else ""))


owctl.init_db()

# Seed a user with a known password
user_id = owctl.execute(
    "INSERT INTO users(username, password_hash, role, enabled, created_at) VALUES(?,?,?,1,?)",
    ("testuser", owctl._hash_password("oldpass123"), "observer", owctl.now())
)

# Login to get a session token
r = client.post("/api/auth/login", json={"username": "testuser", "password": "oldpass123"})
check("login with seeded credentials -> 200", r.status_code == 200, f"got {r.status_code}")
sess = (r.json() or {}).get("session", "")
check("login returns a session token", len(sess) >= 16, f"len={len(sess)}")

# Change password with correct current password
r = client.post(
    "/api/users/me/password-change",
    json={"current_password": "oldpass123", "new_password": "newpass456"},
    headers={"Authorization": f"Bearer {sess}"}
)
check("password change with correct current -> 200", r.status_code == 200, f"got {r.status_code}")
check("password change returns ok", (r.json() or {}).get("ok") is True, str(r.json()))

# Verify new password works for login
r2 = client.post("/api/auth/login", json={"username": "testuser", "password": "newpass456"})
check("login with NEW password -> 200", r2.status_code == 200, f"got {r2.status_code}")
new_sess = (r2.json() or {}).get("session", "")
check("new login returns session", len(new_sess) >= 16, f"len={len(new_sess)}")

# Verify old password no longer works
r3 = client.post("/api/auth/login", json={"username": "testuser", "password": "oldpass123"})
check("login with OLD password -> 401", r3.status_code == 401, f"got {r3.status_code}")

# Wrong current password returns 400
r4 = client.post(
    "/api/users/me/password-change",
    json={"current_password": "wrongpass", "new_password": "another789"},
    headers={"Authorization": f"Bearer {new_sess}"}
)
check("wrong current_password -> 400", r4.status_code == 400, f"got {r4.status_code}: {r4.text}")
check("error message mentions incorrect current", "incorrect" in r4.text.lower(), r4.text[:200])

# New password too short (< 4 chars) returns 400
r5 = client.post(
    "/api/users/me/password-change",
    json={"current_password": "newpass456", "new_password": "abc"},
    headers={"Authorization": f"Bearer {new_sess}"}
)
check("new_password < 4 chars -> 400", r5.status_code == 400, f"got {r5.status_code}: {r5.text}")

# Missing current_password returns 400
r6 = client.post(
    "/api/users/me/password-change",
    json={"new_password": "validnewpass"},
    headers={"Authorization": f"Bearer {new_sess}"}
)
check("missing current_password -> 400", r6.status_code == 400, f"got {r6.status_code}: {r6.text}")

# Missing new_password returns 400
r7 = client.post(
    "/api/users/me/password-change",
    json={"current_password": "newpass456"},
    headers={"Authorization": f"Bearer {new_sess}"}
)
check("missing new_password -> 400", r7.status_code == 400, f"got {r7.status_code}: {r7.text}")

# Disabled user cannot even login (login returns 403)
disabled_id = owctl.execute(
    "INSERT INTO users(username, password_hash, role, enabled, created_at) VALUES(?,?,?,0,?)",
    ("disableduser", owctl._hash_password("disabled123"), "observer", owctl.now())
)
r = client.post("/api/auth/login", json={"username": "disableduser", "password": "disabled123"})
check("disabled account login -> 403", r.status_code == 403, f"got {r.status_code}: {r.text}")

# No authorization header returns 401
r8 = client.post(
    "/api/users/me/password-change",
    json={"current_password": "newpass456", "new_password": "anotherpass"}
)
check("no bearer token -> 401", r8.status_code == 401, f"got {r8.status_code}: {r8.text}")

print(f"\n=== SUMMARY ===\n{sum(1 for _, ok, _ in CHECKS if ok)}/{len(CHECKS)} checks passed")
failed = [n for n, ok, _ in CHECKS if not ok]
if failed:
    for n in failed:
        print(" -", n)
    sys.exit(1)
print("ALL PASSWORD CHANGE CHECKS PASSED")