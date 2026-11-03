#!/usr/bin/env python3
"""Checks for digest scheduling: setting, cadence logic, scheduler integration."""
import os
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

DATA = tempfile.mkdtemp(prefix="owctl-digest-cron-test-")
os.environ["OWCTL_DATA"] = DATA
import owctl  # noqa: E402

owctl.DB_PATH = os.path.join(DATA, "test.db")
owctl.init_db()

ok = 0
fail = 0


def check(name, cond, extra=""):
    global ok, fail
    if cond:
        ok += 1
    else:
        fail += 1
        print(f"FAIL {name}" + (f"  [{extra}]" if extra else ""))


# (a) digest_schedule reads 'never' by default
check("default is never", owctl.digest_schedule() == "never", f"got {owctl.digest_schedule()!r}")

# (b) write/read back daily and weekly
owctl.set_setting("digest_schedule", "daily")
check("set daily -> read daily", owctl.digest_schedule() == "daily", f"got {owctl.digest_schedule()!r}")

owctl.set_setting("digest_schedule", "weekly")
check("set weekly -> read weekly", owctl.digest_schedule() == "weekly", f"got {owctl.digest_schedule()!r}")

owctl.set_setting("digest_schedule", "never")
check("set never -> read never", owctl.digest_schedule() == "never", f"got {owctl.digest_schedule()!r}")

# Reset to never before API tests
owctl.set_setting("digest_schedule", "never")

# (c) invalid value is coerced to 'never'
owctl.set_setting("digest_schedule", "monthly")
check("invalid -> never", owctl.digest_schedule() == "never", f"got {owctl.digest_schedule()!r}")

owctl.set_setting("digest_schedule", "DAILY")  # uppercase
check("uppercase DAILY -> daily", owctl.digest_schedule() == "daily", f"got {owctl.digest_schedule()!r}")

# Reset to never before API tests
owctl.set_setting("digest_schedule", "never")

# (d) pure cadence logic: digest_should_fire
now = time.time()
# never never fires
check("never cadence never fires", owctl.digest_should_fire("never", 0, now) is False)
check("never cadence with old ts never fires", owctl.digest_should_fire("never", now - 999999999, now) is False)

# daily fires after 24h boundary (>= 86400)
check("daily fires exactly at 24h", owctl.digest_should_fire("daily", now - 86400, now) is True)
check("daily fires after 24h+1s", owctl.digest_should_fire("daily", now - 86401, now) is True)
check("daily does NOT fire at 23h59m", owctl.digest_should_fire("daily", now - 86399, now) is False)

# weekly fires after 7d boundary (>= 604800)
check("weekly fires exactly at 7d", owctl.digest_should_fire("weekly", now - 604800, now) is True)
check("weekly fires after 7d+1s", owctl.digest_should_fire("weekly", now - 604801, now) is True)
check("weekly does NOT fire at 6d23h", owctl.digest_should_fire("weekly", now - 604799, now) is False)

# last_sent_ts=0 (never sent) -> fires for daily/weekly
check("daily fires when never sent (ts=0)", owctl.digest_should_fire("daily", 0, now) is True)
check("weekly fires when never sent (ts=0)", owctl.digest_should_fire("weekly", 0, now) is True)

# (e) scheduler integration: the GET /api/settings returns digest_schedule
import asyncio
from fastapi.testclient import TestClient
client = TestClient(owctl.app)

# Need to log in first (first boot sets admin password)
r = client.post("/api/auth/login", json={"username": "admin", "password": "test123"})
check("login works", r.status_code == 200, f"status={r.status_code} body={r.text}")
sess = (r.json() or {}).get("session", "")
check("got session", len(sess) >= 16, f"len={len(sess)}")
auth = {"Authorization": f"Bearer {sess}"}

r = client.get("/api/settings", headers=auth)
check("GET /api/settings has digest_schedule", "digest_schedule" in r.json(), str(r.json()))
check("GET value is never by default", r.json().get("digest_schedule") == "never", r.json())

# (f) PUT /api/settings rejects invalid value
r = client.put("/api/settings", json={"digest_schedule": "monthly"}, headers=auth)
check("PUT invalid -> 400", r.status_code == 400, f"status={r.status_code} body={r.text}")

# (g) PUT /api/settings accepts valid values and persists
for val in ("daily", "weekly", "never"):
    r = client.put("/api/settings", json={"digest_schedule": val}, headers=auth)
    check(f"PUT {val} -> 200", r.status_code == 200, f"status={r.status_code}")
    r2 = client.get("/api/settings", headers=auth)
    check(f"GET after PUT {val} -> {val}", r2.json().get("digest_schedule") == val, r2.json())

print(f"\n{ok}/{ok+fail} checks passed")
if fail:
    sys.exit(1)