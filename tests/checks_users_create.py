#!/usr/bin/env python3
"""checks_users_create.py — POST /api/users must enforce the same password
min-length (>= 4) as first-boot setup, self-service password-change, and the
dashboard. Regression guard: an admin could previously mint a 1-3 char
password (e.g. "abc") through user creation while every other password-setting
path rejected it."""
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ["OWCTL_DATA"] = tempfile.mkdtemp()
os.environ["OWCTL_ALLOW_OPEN"] = "1"
import owctl  # noqa: E402
from starlette.testclient import TestClient

client = TestClient(owctl.app)
FAILS = []


def check(name, cond, extra=""):
    ok = bool(cond)
    print(("ok   " if ok else "FAIL ") + name + (f"  {extra}" if (extra and not ok) else ""))
    if not ok:
        FAILS.append(name)


owctl.init_db()

# 1) A 1-3 char password is rejected at creation (the bug).
r = client.post("/api/users", json={"username": "xshortpw", "password": "abc"})
check("create pw len 3 -> 400", r.status_code == 400, f"{r.status_code} {r.text[:80]}")
check("create pw len 3 -> not created", not owctl.q("SELECT 1 FROM users WHERE username=?", ("xshortpw",)))

r = client.post("/api/users", json={"username": "xshort2", "password": "ab"})
check("create pw len 2 -> 400", r.status_code == 400, f"{r.status_code} {r.text[:80]}")

# 2) Exactly the boundary (len 4) is accepted.
r = client.post("/api/users", json={"username": "ok4", "password": "abcd", "role": "observer"})
check("create pw len 4 -> 200", r.status_code == 200, f"{r.status_code} {r.text[:80]}")
check("create pw len 4 -> row exists", bool(owctl.q("SELECT 1 FROM users WHERE username=?", ("ok4",))))

# 3) Existing validation still intact: empty password -> 400.
r = client.post("/api/users", json={"username": "empty", "password": ""})
check("create pw empty -> 400", r.status_code == 400, f"{r.status_code} {r.text[:80]}")

# 4) A longer password is accepted (no false rejection).
r = client.post("/api/users", json={"username": "longpw", "password": "hunter22", "role": "admin"})
check("create pw len 8 -> 200", r.status_code == 200, f"{r.status_code} {r.text[:80]}")

print()
if FAILS:
    print(f"FAILED: {len(FAILS)} check(s)")
    for f in FAILS:
        print("  - " + f)
    sys.exit(1)
print("ALL USERS_CREATE CHECKS PASSED")
